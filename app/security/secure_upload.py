"""
Модуль для безопасной загрузки файлов.

Предоставляет:
- Конфигурацию допустимых типов файлов, размеров, квот.
- Детектор аномалий (двойное расширение, null-байты, path traversal, zip-бомбы).
- Валидацию MIME-типа и содержимого изображений.
- Управление квотами загрузок (для пользователей и IP).
- Сохранение временных файлов с безопасными именами.
- Функции для чтения файла по частям (chunked) с контролем размера.
Vortex/app/security/secure_upload.py
"""

import os
import hashlib
import secrets
import logging
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from fastapi import UploadFile, HTTPException, Request
from PIL import Image
import PIL
import io
from sqlalchemy.orm import Session
from sqlalchemy import func

logger = logging.getLogger(__name__)
try:
    import magic as _magic_lib
    _MAGIC_AVAILABLE = True
except (ImportError, OSError):
    _magic_lib = None
    _MAGIC_AVAILABLE = False
    logger.warning(
        "python-magic / libmagic не найдены — MIME-валидация будет по расширению. "
        "Установите: pip install python-magic && apt-get install libmagic1"
    )


class FileUploadConfig:
    """Настройки загрузки файлов."""
    from app.config import Config as _Cfg
    MAX_FILE_SIZE = _Cfg.MAX_FILE_BYTES  # from MAX_FILE_MB env (default 2 GB)

    # Ограничения для изображений
    MAX_IMAGE_DIMENSION = 10000
    MIN_IMAGE_DIMENSION = 50

    # Допустимые MIME-типы и соответствующие расширения
    ALLOWED_MIME_TYPES: dict[str, list[str]] = {
        # ── Изображения ──────────────────────────────────────────────────
        'image/jpeg':     ['.jpg', '.jpeg', '.jfif', '.jpe'],   # FIX: добавлены .jfif/.jpe (iPhone, Windows)
        'image/png':      ['.png'],
        'image/webp':     ['.webp'],
        'image/gif':      ['.gif'],
        'image/bmp':      ['.bmp'],
        'image/tiff':     ['.tif', '.tiff'],
        'image/x-adobe-dng': ['.dng'],
        'image/svg+xml':  ['.svg'],
        # HEIC/HEIF (iPhone): magic возвращает разные строки в зависимости от libmagic версии
        'image/heic':     ['.heic', '.heif'],
        'image/heif':     ['.heic', '.heif'],
        # ── Видео ────────────────────────────────────────────────────────
        'video/mp4':        ['.mp4', '.m4v'],
        'video/webm':       ['.webm'],
        'video/quicktime':  ['.mov', '.qt'],
        'video/x-msvideo':  ['.avi'],
        'video/x-matroska': ['.mkv'],
        'video/3gpp':       ['.3gp'],
        # ── Аудио ────────────────────────────────────────────────────────
        'audio/mpeg':       ['.mp3'],
        'audio/ogg':        ['.ogg', '.oga'],
        'audio/wav':        ['.wav'],
        'audio/x-wav':      ['.wav'],
        'audio/webm':       ['.weba'],
        'audio/aac':        ['.aac', '.m4a'],
        'audio/flac':       ['.flac'],
        'audio/x-flac':     ['.flac'],
        'audio/mp4':        ['.m4a'],
        # ── Документы ────────────────────────────────────────────────────
        'application/pdf':  ['.pdf'],
        'text/plain':       ['.txt', '.log', '.md', '.csv'],
        'text/csv':         ['.csv'],
        'text/rtf':         ['.rtf'],
        'application/rtf':  ['.rtf'],
        'application/msword': ['.doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
        'application/vnd.ms-excel': ['.xls'],
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
        'application/vnd.ms-powerpoint': ['.ppt'],
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
        'application/vnd.oasis.opendocument.text': ['.odt'],
        'application/vnd.oasis.opendocument.spreadsheet': ['.ods'],
        'application/vnd.oasis.opendocument.presentation': ['.odp'],
        'text/html':        ['.html', '.htm', '.vxpage.html'],
        'text/css':         ['.css'],
        'text/javascript':  ['.js', '.mjs'],
        'text/typescript':  ['.ts', '.tsx'],
        'application/json': ['.json'],
        'application/xml':  ['.xml'],
        'text/xml':         ['.xml'],
        'text/yaml':        ['.yaml', '.yml'],
        'text/x-python':    ['.py'],
        'text/x-php':       ['.php'],
        'text/x-java':      ['.java'],
        'text/x-c':         ['.c', '.h'],
        'text/x-c++':       ['.cpp', '.cxx', '.hpp'],
        'text/x-csharp':    ['.cs'],
        'text/x-go':        ['.go'],
        'text/x-rust':      ['.rs'],
        'text/x-ruby':      ['.rb'],
        'text/x-swift':     ['.swift'],
        'text/x-kotlin':    ['.kt', '.kts'],
        'text/x-shellscript': ['.sh', '.bash'],
        'text/x-sql':       ['.sql'],
        'application/x-vortex-sticker': ['.sticker'],
        # ── Архивы ───────────────────────────────────────────────────────
        'application/zip':                ['.zip'],
        'application/x-zip-compressed':   ['.zip'],
        'application/x-rar-compressed':   ['.rar'],
        'application/x-7z-compressed':    ['.7z'],
        'application/gzip':               ['.gz'],
        'application/x-tar':              ['.tar'],
        # ── Зашифрованные файлы (E2E) ─────────────────────────────────
        'application/octet-stream':       ['.enc', '.bin'],
    }
    ALLOWED_EXTENSIONS = {ext for exts in ALLOWED_MIME_TYPES.values() for ext in exts}

    # Квоты загрузок
    MAX_FILES_PER_HOUR = 10
    MAX_FILES_PER_DAY = 50
    MAX_MEMORY_BUFFER = 100 * 1024 * 1024  # 100 МБ
    # Время жизни временных файлов в секундах (для очистки)
    TEMP_FILE_LIFETIME = 300

    # Включать ли дополнительные проверки содержимого
    REQUIRE_CONTENT_VALIDATION = True
    CHECK_FOR_MALICIOUS_CONTENT = True


# ── EXIF Stripping ───────────────────────────────────────────────────────────

def strip_exif(content: bytes, mime_type: str) -> bytes:
    """
    Strip EXIF/metadata from images before storage.

    Removes GPS coordinates, camera model, timestamps — prevents geolocation leaks.
    Preserves image quality (lossless for PNG, quality=95 for JPEG).
    Returns original content unchanged for non-image files.
    """
    if not mime_type or not mime_type.startswith("image/"):
        return content

    try:
        img = Image.open(io.BytesIO(content))

        # Create clean image without EXIF
        clean = Image.new(img.mode, img.size)
        clean.putdata(list(img.getdata()))

        # Preserve ICC profile if present (color accuracy, not privacy-sensitive)
        icc = img.info.get("icc_profile")

        buf = io.BytesIO()
        save_kwargs = {}
        if icc:
            save_kwargs["icc_profile"] = icc

        fmt = img.format or "JPEG"
        if fmt.upper() in ("JPEG", "JPG"):
            clean.save(buf, format="JPEG", quality=95, **save_kwargs)
        elif fmt.upper() == "PNG":
            clean.save(buf, format="PNG", **save_kwargs)
        elif fmt.upper() == "WEBP":
            clean.save(buf, format="WEBP", quality=95, **save_kwargs)
        else:
            # Unknown format — return original (don't risk corruption)
            return content

        result = buf.getvalue()
        stripped_size = len(content) - len(result)
        if stripped_size > 0:
            logger.debug(f"EXIF stripped: {stripped_size} bytes removed from {fmt}")
        return result

    except Exception as e:
        logger.warning(f"EXIF strip failed ({e}), returning original")
        return content


def _strip_mp4_atoms(content: bytes) -> bytes:
    """
    Pure-Python MP4/MOV metadata removal.

    Parses ISO BMFF atom structure, removes metadata-bearing atoms
    (udta, meta, XMP_, uuid) from inside moov container.
    Works without ffmpeg.
    """
    import struct

    METADATA_ATOMS = {b"udta", b"meta", b"XMP_", b"uuid"}

    def parse_atoms(data: bytes, offset: int = 0, end: int | None = None) -> list:
        """Parse top-level atoms, return list of (offset, size, type, has_children)."""
        if end is None:
            end = len(data)
        atoms = []
        pos = offset
        while pos + 8 <= end:
            size = struct.unpack(">I", data[pos:pos + 4])[0]
            atype = data[pos + 4:pos + 8]
            if size == 0:
                size = end - pos
            elif size == 1 and pos + 16 <= end:
                size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]
            if size < 8 or pos + size > end:
                break
            atoms.append((pos, size, atype))
            pos += size
        return atoms

    def rebuild_moov(data: bytes, moov_off: int, moov_size: int) -> bytes:
        """Rebuild moov atom without metadata sub-atoms."""
        children = parse_atoms(data, moov_off + 8, moov_off + moov_size)
        parts = []
        removed = 0
        for coff, csize, ctype in children:
            if ctype in METADATA_ATOMS:
                removed += csize
                continue
            parts.append(data[coff:coff + csize])
        if removed == 0:
            return data[moov_off:moov_off + moov_size]
        body = b"".join(parts)
        new_size = 8 + len(body)
        return struct.pack(">I", new_size) + b"moov" + body

    try:
        top_atoms = parse_atoms(content)
        parts = []
        changed = False
        for aoff, asize, atype in top_atoms:
            if atype == b"moov":
                new_moov = rebuild_moov(content, aoff, asize)
                if len(new_moov) != asize:
                    changed = True
                parts.append(new_moov)
            elif atype in METADATA_ATOMS:
                changed = True
                continue
            else:
                parts.append(content[aoff:aoff + asize])
        if changed:
            result = b"".join(parts)
            logger.debug("MP4 metadata atoms stripped (pure-Python): %d bytes removed",
                         len(content) - len(result))
            return result
    except Exception as e:
        logger.debug("MP4 atom stripping failed: %s", e)

    return content


def _strip_id3_tags(content: bytes) -> bytes:
    """
    Pure-Python ID3 tag removal for MP3 files.

    Strips:
      - ID3v2 header (beginning of file, variable size)
      - ID3v1 footer (last 128 bytes)
      - APEv2 footer
    Works without ffmpeg or mutagen.
    """
    import struct
    data = bytearray(content)
    changed = False

    # Strip ID3v2 at the beginning
    if data[:3] == b"ID3" and len(data) > 10:
        # ID3v2 size is syncsafe integer (4 bytes, 7 bits each)
        sz_bytes = data[6:10]
        tag_size = (
            (sz_bytes[0] & 0x7F) << 21 |
            (sz_bytes[1] & 0x7F) << 14 |
            (sz_bytes[2] & 0x7F) << 7 |
            (sz_bytes[3] & 0x7F)
        )
        header_size = 10 + tag_size
        # Check for footer flag (bit 4 of flags byte)
        if data[5] & 0x10:
            header_size += 10
        if header_size < len(data):
            data = data[header_size:]
            changed = True
            logger.debug("ID3v2 tag stripped: %d bytes", header_size)

    # Strip ID3v1 at the end (last 128 bytes starting with "TAG")
    if len(data) > 128 and data[-128:-125] == b"TAG":
        data = data[:-128]
        changed = True
        logger.debug("ID3v1 tag stripped: 128 bytes")

    # Strip APEv2 at the end
    if len(data) > 32 and data[-32:-24] == b"APETAGEX":
        ape_size = struct.unpack("<I", data[-20:-16])[0] + 32
        if ape_size < len(data):
            data = data[:-ape_size]
            changed = True
            logger.debug("APEv2 tag stripped: %d bytes", ape_size)

    return bytes(data) if changed else content


def strip_video_metadata(content: bytes, mime_type: str) -> bytes:
    """
    Strip metadata from video files (GPS, camera, creation time, software).

    Priority: ffmpeg (best) → pure-Python MP4 atom removal (fallback).
    """
    if not mime_type or not mime_type.startswith("video/"):
        return content

    import shutil
    import subprocess
    import tempfile

    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg:
        try:
            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as inp:
                inp.write(content)
                inp_path = inp.name
            out_path = inp_path + ".clean.mp4"
            result = subprocess.run(
                [ffmpeg, "-i", inp_path, "-map_metadata", "-1",
                 "-c", "copy", "-fflags", "+bitexact",
                 "-movflags", "+faststart", "-y", out_path],
                capture_output=True, timeout=60,
            )
            if result.returncode == 0:
                cleaned = Path(out_path).read_bytes()
                logger.debug(f"Video metadata stripped via ffmpeg: {len(content) - len(cleaned)} bytes removed")
                os.unlink(inp_path)
                os.unlink(out_path)
                return cleaned
            os.unlink(inp_path)
            if os.path.exists(out_path):
                os.unlink(out_path)
        except Exception as e:
            logger.debug(f"Video metadata strip via ffmpeg failed: {e}")

    # Fallback: pure-Python MP4/MOV atom removal
    if mime_type in ("video/mp4", "video/quicktime", "video/x-m4v", "video/mp4v-es"):
        return _strip_mp4_atoms(content)

    logger.debug("No stripping method available for %s", mime_type)
    return content


def strip_audio_metadata(content: bytes, mime_type: str) -> bytes:
    """
    Strip metadata from audio files (ID3 tags, Vorbis comments, etc.).

    Uses ffmpeg if available. Falls back to mutagen if installed.
    """
    if not mime_type or not mime_type.startswith("audio/"):
        return content

    import shutil
    import subprocess
    import tempfile

    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg:
        # Determine output format from mime
        ext_map = {
            "audio/mpeg": (".mp3", ["-c", "copy"]),
            "audio/ogg": (".ogg", ["-c", "copy"]),
            "audio/wav": (".wav", ["-c", "copy"]),
            "audio/x-wav": (".wav", ["-c", "copy"]),
            "audio/aac": (".m4a", ["-c", "copy"]),
            "audio/mp4": (".m4a", ["-c", "copy"]),
            "audio/flac": (".flac", ["-c", "copy"]),
            "audio/x-flac": (".flac", ["-c", "copy"]),
            "audio/webm": (".webm", ["-c", "copy"]),
        }
        ext, codec_args = ext_map.get(mime_type, (".bin", ["-c", "copy"]))
        try:
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as inp:
                inp.write(content)
                inp_path = inp.name
            out_path = inp_path + ".clean" + ext
            result = subprocess.run(
                [ffmpeg, "-i", inp_path, "-map_metadata", "-1"] + codec_args + ["-y", out_path],
                capture_output=True, timeout=60,
            )
            if result.returncode == 0:
                cleaned = Path(out_path).read_bytes()
                logger.debug(f"Audio metadata stripped: {len(content) - len(cleaned)} bytes removed")
                os.unlink(inp_path)
                os.unlink(out_path)
                return cleaned
            os.unlink(inp_path)
            if os.path.exists(out_path):
                os.unlink(out_path)
        except Exception as e:
            logger.debug(f"Audio metadata strip via ffmpeg failed: {e}")
    else:
        # Fallback 1: try mutagen for tag removal
        try:
            import mutagen
            import tempfile as _tf
            with _tf.NamedTemporaryFile(suffix=".tmp", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            f = mutagen.File(tmp_path)
            if f is not None:
                f.delete()
                f.save()
                cleaned = Path(tmp_path).read_bytes()
                os.unlink(tmp_path)
                return cleaned
            os.unlink(tmp_path)
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Audio metadata strip via mutagen failed: {e}")

        # Fallback 2: pure-Python ID3 stripping for MP3
        if mime_type in ("audio/mpeg", "audio/mp3"):
            return _strip_id3_tags(content)

        # Fallback 3: strip MP4/M4A atoms for AAC containers
        if mime_type in ("audio/mp4", "audio/aac", "audio/x-m4a"):
            return _strip_mp4_atoms(content)

        logger.debug("No audio metadata stripping method available for %s", mime_type)

    return content


def strip_pdf_metadata(content: bytes) -> bytes:
    """
    Strip metadata from PDF files (author, creator, producer, creation/mod dates).

    Uses pikepdf if available, fallback to PyPDF2/pypdf.
    """
    # Try pikepdf first (best PDF library)
    try:
        import pikepdf
        pdf = pikepdf.open(io.BytesIO(content))
        # Clear /Info dictionary
        with pdf.open_metadata() as meta:
            for key in list(meta.keys()):
                del meta[key]
        if "/Info" in pdf.trailer:
            del pdf.trailer["/Info"]
        buf = io.BytesIO()
        pdf.save(buf)
        result = buf.getvalue()
        logger.debug(f"PDF metadata stripped via pikepdf: {len(content) - len(result)} bytes delta")
        return result
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"PDF metadata strip via pikepdf failed: {e}")

    # Fallback: pypdf
    try:
        from pypdf import PdfReader, PdfWriter
        reader = PdfReader(io.BytesIO(content))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        # Clear metadata
        writer.add_metadata({
            "/Producer": "",
            "/Creator": "",
            "/Author": "",
            "/Title": "",
            "/Subject": "",
            "/CreationDate": "",
            "/ModDate": "",
        })
        buf = io.BytesIO()
        writer.write(buf)
        result = buf.getvalue()
        logger.debug(f"PDF metadata stripped via pypdf")
        return result
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"PDF metadata strip via pypdf failed: {e}")

    logger.debug("No PDF library available — PDF metadata NOT stripped")
    return content


def strip_all_metadata(content: bytes, mime_type: str) -> bytes:
    """
    Universal metadata stripper. Dispatches to format-specific strippers.

    Supported:
      - Images (JPEG, PNG, WebP) → strip_exif()
      - Video (MP4, WebM, MOV, AVI, MKV) → strip_video_metadata() via ffmpeg
      - Audio (MP3, OGG, WAV, AAC, FLAC) → strip_audio_metadata() via ffmpeg/mutagen
      - PDF → strip_pdf_metadata() via pikepdf/pypdf
    """
    if not mime_type:
        return content

    if mime_type.startswith("image/"):
        return strip_exif(content, mime_type)
    elif mime_type.startswith("video/"):
        return strip_video_metadata(content, mime_type)
    elif mime_type.startswith("audio/"):
        return strip_audio_metadata(content, mime_type)
    elif mime_type == "application/pdf":
        return strip_pdf_metadata(content)

    return content


def generate_encrypted_thumbnail(content: bytes, mime_type: str, max_dim: int = 200) -> Optional[bytes]:
    """
    Generate a small thumbnail for image preview.

    Returns JPEG bytes (quality=60) or None for non-images.
    Thumbnail is EXIF-clean by construction.
    """
    if not mime_type or not mime_type.startswith("image/"):
        return None
    try:
        img = Image.open(io.BytesIO(content))
        img.thumbnail((max_dim, max_dim), Image.LANCZOS)
        if img.mode != "RGB":
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=60)
        return buf.getvalue()
    except Exception:
        return None


class FileAnomalyDetector:
    """
    Класс для обнаружения подозрительных файлов.
    """

    @staticmethod
    def detect_double_extension(filename: str) -> bool:
        """
        Проверяет наличие двойного расширения с опасным промежуточным расширением.
        Флагирует: shell.php.jpg, virus.exe.png
        НЕ флагирует: photo.vacation.jpg, my.photo.png, photo 2024-01-01 12.34.jpg
        """
        _DANGEROUS_EXTS = frozenset({
            '.php', '.php3', '.php4', '.php5', '.phtml',
            '.asp', '.aspx', '.ascx', '.ashx',
            '.jsp', '.jspx', '.jws',
            '.cgi', '.pl', '.py', '.rb', '.sh', '.bash',
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs',
        })
        name  = Path(filename).name
        parts = name.split('.')
        if len(parts) <= 2:
            return False
        # Только промежуточные части (исключаем первую часть и последнее расширение)
        intermediate = {'.' + p.lower() for p in parts[1:-1]}
        return bool(intermediate & _DANGEROUS_EXTS)

    @staticmethod
    def detect_null_bytes(filename: str) -> bool:
        """Проверяет наличие null-байтов в имени файла."""
        return '\x00' in filename

    @staticmethod
    def detect_path_traversal(filename: str) -> bool:
        """
        Проверяет наличие признаков path traversal или инъекций.
        """
        dangerous_patterns = [
            '..', '/', '\\', '~',
            'C:', 'D:',
            '/etc/', '/bin/', '/usr/bin/',
            '<?php', '<script', 'javascript:'
        ]
        return any(pattern in filename for pattern in dangerous_patterns)

    @staticmethod
    async def validate_image_content(content: bytes) -> Tuple[bool, Optional[str]]:
        """
        Проверяет, что содержимое является корректным изображением,
        не превышает допустимые размеры и имеет нормальное соотношение сторон.
        """
        try:
            if len(content) < 12:
                return False, "Файл слишком мал для проверки"

            img = Image.open(io.BytesIO(content))

            # Конвертируем в RGB, если нужно (удаляем альфа-канал и т.п.)
            if hasattr(img, 'mode'):
                if img.mode in ['RGBA', 'CMYK', 'YCbCr', 'LAB', 'HSV']:
                    img = img.convert('RGB')

            width, height = img.size
            if width > FileUploadConfig.MAX_IMAGE_DIMENSION or height > FileUploadConfig.MAX_IMAGE_DIMENSION:
                return False, f"Размер изображения слишком большой: {width}x{height}"

            if width < FileUploadConfig.MIN_IMAGE_DIMENSION or height < FileUploadConfig.MIN_IMAGE_DIMENSION:
                return False, f"Размер изображения слишком маленький: {width}x{height}"

            aspect_ratio = width / height if height > 0 else 0
            if aspect_ratio > 10 or aspect_ratio < 0.1:
                return False, f"Некорректное соотношение сторон: {aspect_ratio:.2f}"

            img.close()
            return True, None

        except PIL.UnidentifiedImageError:
            return False, "Невозможно идентифицировать изображение"
        except Exception as e:
            logger.warning(f"Ошибка валидации изображения: {str(e)}")
            return False, f"Ошибка обработки изображения: {str(e)[:100]}"

    @staticmethod
    def calculate_file_complexity(content: bytes) -> float:
        """
        Вычисляет энтропию содержимого файла (Shannon entropy, 0–8 бит).
        Высокая энтропия может указывать на сжатые или зашифрованные данные (zip-бомбы).
        """
        import math

        if len(content) == 0:
            return 0.0

        freq = {}
        for byte in content:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        total = len(content)
        for count in freq.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def detect_zip_bomb_indicators(content: bytes) -> bool:
        """
        Проверяет, не является ли файл zip-бомбой (очень маленький архив с огромной энтропией).
        """
        if len(content) < 1000:
            return False

        archive_magic_numbers = [
            b'PK\x03\x04',      # ZIP
            b'PK\x05\x06',      # ZIP (central directory)
            b'PK\x07\x08',      # ZIP (spanned)
            b'\x1f\x8b',        # GZIP
            b'BZh',             # BZIP2
            b'\x50\x4b',        # ZIP (альтернатива)
        ]

        for magic_num in archive_magic_numbers:
            if content.startswith(magic_num):
                entropy = FileAnomalyDetector.calculate_file_complexity(content)
                if entropy > 7.5:   # Эмпирическое значение
                    return True

        return False


class UploadQuotaManager:
    """
    Менеджер квот загрузок, использующий БД для учёта количества файлов от пользователя и IP.
    """

    def __init__(self, db: Session):
        self.db = db

    async def check_user_quota(self, user_id: Optional[int], client_ip: str) -> Tuple[bool, Optional[str]]:
        """
        Проверяет, не превысил ли пользователь или IP лимиты загрузок.
        Возвращает (True, None) если лимиты не превышены, иначе (False, сообщение).
        """
        try:
            # Импортируем модель внутри функции, чтобы избежать циклических импортов
            from app.models import UploadQuota

            current_time = datetime.now(timezone.utc)
            hour_ago = current_time - timedelta(hours=1)
            day_ago = current_time - timedelta(days=1)

            if user_id:
                # Часовая квота для пользователя
                hour_count = self.db.query(func.count(UploadQuota.id)).filter(
                    UploadQuota.user_id == user_id,
                    UploadQuota.uploaded_at >= hour_ago
                ).scalar() or 0

                if hour_count >= FileUploadConfig.MAX_FILES_PER_HOUR:
                    return False, "Превышена часовая квота загрузок"

                # Дневная квота для пользователя
                day_count = self.db.query(func.count(UploadQuota.id)).filter(
                    UploadQuota.user_id == user_id,
                    UploadQuota.uploaded_at >= day_ago
                ).scalar() or 0

                if day_count >= FileUploadConfig.MAX_FILES_PER_DAY:
                    return False, "Превышена дневная квота загрузок"

            # Проверка квоты по IP (более строгая: в два раза больше лимита пользователя)
            ip_hour_count = self.db.query(func.count(UploadQuota.id)).filter(
                UploadQuota.client_ip == client_ip,
                UploadQuota.uploaded_at >= hour_ago
            ).scalar() or 0

            if ip_hour_count >= FileUploadConfig.MAX_FILES_PER_HOUR * 2:
                return False, "Превышен лимит загрузок с вашего IP"

            return True, None
        except Exception as e:
            logger.error(f"Ошибка проверки квот: {e}")
            return False, "Ошибка проверки квот"

    async def record_upload(self, user_id: Optional[int], client_ip: str, file_size: int, file_hash: Optional[str] = None):
        """
        Записывает факт загрузки в БД для учёта квот.
        """
        try:
            from app.models import UploadQuota

            upload_record = UploadQuota(
                user_id=user_id,
                client_ip=client_ip,
                file_size=file_size,
                file_hash=file_hash,
                uploaded_at=datetime.now(timezone.utc)
            )
            self.db.add(upload_record)
            self.db.commit()
        except Exception as e:
            logger.error(f"Ошибка записи квоты: {e}")
            self.db.rollback()


def generate_secure_filename(extension: str) -> str:
    """
    Генерирует безопасное имя файла: случайная строка + расширение.
    Используется secrets.token_urlsafe для криптостойкости.
    """
    return secrets.token_urlsafe(16) + extension


def calculate_file_hash(content: bytes) -> str:
    """Возвращает SHA256 хеш содержимого файла."""
    return hashlib.sha256(content).hexdigest()


def validate_file_mime_type(content: bytes, filename: str) -> Tuple[bool, Optional[str]]:
    """
    Проверяет MIME-тип файла по первым байтам и соответствие расширения.
    Возвращает (успех, MIME-тип или сообщение об ошибке).
    """
    file_ext = Path(filename).suffix.lower()

    # ── Шаг 1: определяем MIME по magic bytes (если libmagic доступна) ───────
    if _MAGIC_AVAILABLE and _magic_lib is not None:
        try:
            mime = _magic_lib.from_buffer(content[:4096], mime=True)
        except Exception as e:
            logger.warning(f"libmagic ошибка: {e} — переходим к fallback по расширению")
            mime = None
    else:
        mime = None

    # ── Шаг 2: если magic не дала результат — определяем по расширению ───────
    if mime is None:
        # Fallback: ищем MIME по расширению файла
        ext_to_mime = {
            ext: mime_type
            for mime_type, exts in FileUploadConfig.ALLOWED_MIME_TYPES.items()
            for ext in exts
        }
        mime = ext_to_mime.get(file_ext)
        if mime is None:
            return False, f"Неподдерживаемое расширение файла: {file_ext}"

    # ── Шаг 2.5: encrypted files (E2E) — magic bytes unrecognisable ────────
    # If libmagic reports octet-stream but the original extension is a known
    # allowed type, accept it as octet-stream (encrypted payload).
    if mime == 'application/octet-stream':
        ext_to_mime = {
            ext: mt
            for mt, exts in FileUploadConfig.ALLOWED_MIME_TYPES.items()
            for ext in exts
        }
        if file_ext in ext_to_mime:
            # E2E encrypted file — use extension-based mime (libmagic can't read encrypted bytes)
            return True, ext_to_mime[file_ext]

    # ── Шаг 3: проверяем что MIME входит в белый список ─────────────────────
    if mime not in FileUploadConfig.ALLOWED_MIME_TYPES:
        # Попытка нормализации: некоторые libmagic версии возвращают x-субтипы
        # например 'audio/x-wav' вместо 'audio/wav' или 'image/x-png' вместо 'image/png'
        normalized = mime.replace('/x-', '/', 1)
        if normalized in FileUploadConfig.ALLOWED_MIME_TYPES:
            mime = normalized
        else:
            return False, f"Неподдерживаемый тип файла: {mime}"

    # ── Шаг 4: проверяем расширение — мягкая проверка ───────────────────────
    expected_exts = FileUploadConfig.ALLOWED_MIME_TYPES.get(mime, [])
    if file_ext and expected_exts and file_ext not in expected_exts:
        mime_category = mime.split('/')[0]
        # Находим все расширения для данной категории
        all_category_exts: set[str] = set()
        for m, exts in FileUploadConfig.ALLOWED_MIME_TYPES.items():
            if m.startswith(mime_category + '/'):
                all_category_exts.update(exts)
        if file_ext not in all_category_exts:
            return False, (
                f"Расширение «{file_ext}» не соответствует типу файла «{mime}». "
                f"Ожидаются: {', '.join(expected_exts)}"
            )

    return True, mime


def save_temp_file(content: bytes, extension: str) -> Tuple[Path, Path]:
    """
    Сохраняет содержимое во временный файл с безопасным именем.
    Возвращает кортеж (путь к временной директории, путь к файлу).
    """
    temp_dir = Path(tempfile.mkdtemp(prefix="secure_upload_"))
    safe_filename = generate_secure_filename(extension)
    temp_file_path = temp_dir / safe_filename

    try:
        with open(temp_file_path, 'wb') as f:
            f.write(content)

        # Устанавливаем права только для владельца
        os.chmod(temp_file_path, 0o600)
        return temp_dir, temp_file_path
    except Exception as e:
        logger.error(f"Ошибка сохранения временного файла: {e}")
        raise


def cleanup_temp_files(temp_dir: Path, temp_file_path: Path):
    """
    Удаляет временный файл и, если директория пуста, удаляет её.
    """
    try:
        if temp_file_path.exists() and temp_file_path.parent == temp_dir:
            os.remove(temp_file_path)
        if temp_dir.exists():
            if not any(temp_dir.iterdir()):
                os.rmdir(temp_dir)
    except Exception as e:
        logger.warning(f"Ошибка при очистке временных файлов: {str(e)}")


async def read_file_chunked(file: UploadFile, max_size: int = FileUploadConfig.MAX_FILE_SIZE) -> Tuple[bytes, int]:
    """
    Читает файл по частям (chunked), контролируя общий размер.
    Возвращает кортеж (содержимое, размер в байтах).
    При превышении max_size выбрасывает HTTPException с кодом 413.
    """
    file_content = bytearray()
    total_size = 0

    while True:
        chunk = await file.read(8192)  # читаем по 8 KB
        if not chunk:
            break

        total_size += len(chunk)
        if total_size > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"Файл слишком большой. Максимальный размер: {max_size // 1024 // 1024}MB"
            )

        file_content.extend(chunk)

    return bytes(file_content), total_size