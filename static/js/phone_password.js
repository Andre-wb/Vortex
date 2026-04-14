// static/js/phone_password.js
// Password strength indicator, password confirmation, international phone formatting.

import { $ } from './utils.js';

// ============================================================================
// COUNTRY DATA — flag, name, dial code, phone format pattern
// Sorted by most common usage first, then alphabetically.
// Format: X = digit, space/dash are literal separators.
// ============================================================================
// Helper: build flag emoji from 2-letter ISO code
const _f = (cc) => String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));

const COUNTRIES = [
    // ── Популярные (вверху для быстрого доступа) ────────────────────────
    { code: 'RU', flag: _f('RU'), name: 'Россия',              dial: '+7',    fmt: 'XXX XXX XX XX' },
    { code: 'US', flag: _f('US'), name: 'United States',       dial: '+1',    fmt: 'XXX XXX XXXX' },
    { code: 'GB', flag: _f('GB'), name: 'United Kingdom',      dial: '+44',   fmt: 'XXXX XXXXXX' },
    { code: 'UA', flag: _f('UA'), name: 'Україна',             dial: '+380',  fmt: 'XX XXX XX XX' },
    { code: 'DE', flag: _f('DE'), name: 'Deutschland',         dial: '+49',   fmt: 'XXX XXXXXXXX' },
    { code: 'FR', flag: _f('FR'), name: 'France',              dial: '+33',   fmt: 'X XX XX XX XX' },
    { code: 'CN', flag: _f('CN'), name: '中国',                dial: '+86',   fmt: 'XXX XXXX XXXX' },
    { code: 'IN', flag: _f('IN'), name: 'India',               dial: '+91',   fmt: 'XXXXX XXXXX' },
    { code: 'BR', flag: _f('BR'), name: 'Brasil',              dial: '+55',   fmt: 'XX XXXXX XXXX' },
    { code: 'KZ', flag: _f('KZ'), name: 'Қазақстан',           dial: '+7',    fmt: 'XXX XXX XX XX' },

    // ── Зона 1: NANP (Сев.Америка + Карибы) ────────────────────────────
    { code: 'CA', flag: _f('CA'), name: 'Canada',              dial: '+1',    fmt: 'XXX XXX XXXX' },
    { code: 'BS', flag: _f('BS'), name: 'Bahamas',             dial: '+1242', fmt: 'XXX XXXX' },
    { code: 'BB', flag: _f('BB'), name: 'Barbados',            dial: '+1246', fmt: 'XXX XXXX' },
    { code: 'AI', flag: _f('AI'), name: 'Anguilla',            dial: '+1264', fmt: 'XXX XXXX' },
    { code: 'AG', flag: _f('AG'), name: 'Antigua & Barbuda',   dial: '+1268', fmt: 'XXX XXXX' },
    { code: 'VG', flag: _f('VG'), name: 'British Virgin Is.',  dial: '+1284', fmt: 'XXX XXXX' },
    { code: 'VI', flag: _f('VI'), name: 'US Virgin Islands',   dial: '+1340', fmt: 'XXX XXXX' },
    { code: 'KY', flag: _f('KY'), name: 'Cayman Islands',      dial: '+1345', fmt: 'XXX XXXX' },
    { code: 'BM', flag: _f('BM'), name: 'Bermuda',             dial: '+1441', fmt: 'XXX XXXX' },
    { code: 'GD', flag: _f('GD'), name: 'Grenada',             dial: '+1473', fmt: 'XXX XXXX' },
    { code: 'TC', flag: _f('TC'), name: 'Turks & Caicos',      dial: '+1649', fmt: 'XXX XXXX' },
    { code: 'JM', flag: _f('JM'), name: 'Jamaica',             dial: '+1876', fmt: 'XXX XXXX' },
    { code: 'MS', flag: _f('MS'), name: 'Montserrat',          dial: '+1664', fmt: 'XXX XXXX' },
    { code: 'MP', flag: _f('MP'), name: 'N. Mariana Islands',  dial: '+1670', fmt: 'XXX XXXX' },
    { code: 'GU', flag: _f('GU'), name: 'Guam',                dial: '+1671', fmt: 'XXX XXXX' },
    { code: 'AS', flag: _f('AS'), name: 'American Samoa',      dial: '+1684', fmt: 'XXX XXXX' },
    { code: 'SX', flag: _f('SX'), name: 'Sint Maarten',        dial: '+1721', fmt: 'XXX XXXX' },
    { code: 'LC', flag: _f('LC'), name: 'Saint Lucia',         dial: '+1758', fmt: 'XXX XXXX' },
    { code: 'DM', flag: _f('DM'), name: 'Dominica',            dial: '+1767', fmt: 'XXX XXXX' },
    { code: 'VC', flag: _f('VC'), name: 'St Vincent & Grenad.',dial: '+1784', fmt: 'XXX XXXX' },
    { code: 'PR', flag: _f('PR'), name: 'Puerto Rico',         dial: '+1787', fmt: 'XXX XXXX' },
    { code: 'DO', flag: _f('DO'), name: 'Rep. Dominicana',     dial: '+1809', fmt: 'XXX XXXX' },
    { code: 'TT', flag: _f('TT'), name: 'Trinidad & Tobago',   dial: '+1868', fmt: 'XXX XXXX' },
    { code: 'KN', flag: _f('KN'), name: 'Saint Kitts & Nevis', dial: '+1869', fmt: 'XXX XXXX' },

    // ── Зона 2: Африка ─────────────────────────────────────────────────
    { code: 'EG', flag: _f('EG'), name: 'مصر (Egypt)',          dial: '+20',   fmt: 'XXX XXX XXXX' },
    { code: 'SS', flag: _f('SS'), name: 'South Sudan',          dial: '+211',  fmt: 'XX XXX XXXX' },
    { code: 'MA', flag: _f('MA'), name: 'المغرب (Morocco)',     dial: '+212',  fmt: 'XX XXX XXXX' },
    { code: 'EH', flag: _f('EH'), name: 'Western Sahara',        dial: '+212',  fmt: 'XXX XXX XXX' },
    { code: 'DZ', flag: _f('DZ'), name: 'الجزائر (Algeria)',    dial: '+213',  fmt: 'XXX XX XX XX' },
    { code: 'TN', flag: _f('TN'), name: 'تونس (Tunisia)',       dial: '+216',  fmt: 'XX XXX XXX' },
    { code: 'LY', flag: _f('LY'), name: 'ليبيا (Libya)',        dial: '+218',  fmt: 'XX XXX XXXX' },
    { code: 'GM', flag: _f('GM'), name: 'Gambia',               dial: '+220',  fmt: 'XXX XXXX' },
    { code: 'SN', flag: _f('SN'), name: 'Sénégal',             dial: '+221',  fmt: 'XX XXX XXXX' },
    { code: 'MR', flag: _f('MR'), name: 'Mauritanie',           dial: '+222',  fmt: 'XX XX XX XX' },
    { code: 'ML', flag: _f('ML'), name: 'Mali',                 dial: '+223',  fmt: 'XX XX XX XX' },
    { code: 'GN', flag: _f('GN'), name: 'Guinée',              dial: '+224',  fmt: 'XXX XX XX XX' },
    { code: 'CI', flag: _f('CI'), name: "Côte d'Ivoire",       dial: '+225',  fmt: 'XX XX XX XXXX' },
    { code: 'BF', flag: _f('BF'), name: 'Burkina Faso',         dial: '+226',  fmt: 'XX XX XX XX' },
    { code: 'NE', flag: _f('NE'), name: 'Niger',                dial: '+227',  fmt: 'XX XX XX XX' },
    { code: 'TG', flag: _f('TG'), name: 'Togo',                 dial: '+228',  fmt: 'XX XXX XXX' },
    { code: 'BJ', flag: _f('BJ'), name: 'Bénin',               dial: '+229',  fmt: 'XX XX XXXX' },
    { code: 'MU', flag: _f('MU'), name: 'Mauritius',            dial: '+230',  fmt: 'XXXX XXXX' },
    { code: 'LR', flag: _f('LR'), name: 'Liberia',              dial: '+231',  fmt: 'XXX XXX XXXX' },
    { code: 'SL', flag: _f('SL'), name: 'Sierra Leone',         dial: '+232',  fmt: 'XX XXXXXX' },
    { code: 'GH', flag: _f('GH'), name: 'Ghana',                dial: '+233',  fmt: 'XX XXX XXXX' },
    { code: 'NG', flag: _f('NG'), name: 'Nigeria',              dial: '+234',  fmt: 'XXX XXX XXXX' },
    { code: 'TD', flag: _f('TD'), name: 'Tchad',                dial: '+235',  fmt: 'XX XX XX XX' },
    { code: 'CF', flag: _f('CF'), name: 'Centrafrique',          dial: '+236',  fmt: 'XX XX XX XX' },
    { code: 'CM', flag: _f('CM'), name: 'Cameroun',              dial: '+237',  fmt: 'XXXX XXXX' },
    { code: 'CV', flag: _f('CV'), name: 'Cabo Verde',            dial: '+238',  fmt: 'XXX XXXX' },
    { code: 'ST', flag: _f('ST'), name: 'São Tomé e Príncipe',  dial: '+239',  fmt: 'XX XXXXX' },
    { code: 'GQ', flag: _f('GQ'), name: 'Guinea Ecuatorial',     dial: '+240',  fmt: 'XXX XXX XXX' },
    { code: 'GA', flag: _f('GA'), name: 'Gabon',                 dial: '+241',  fmt: 'X XX XX XX' },
    { code: 'CG', flag: _f('CG'), name: 'Congo',                 dial: '+242',  fmt: 'XX XXX XXXX' },
    { code: 'CD', flag: _f('CD'), name: 'RD Congo',              dial: '+243',  fmt: 'XXX XXX XXX' },
    { code: 'AO', flag: _f('AO'), name: 'Angola',                dial: '+244',  fmt: 'XXX XXX XXX' },
    { code: 'GW', flag: _f('GW'), name: 'Guiné-Bissau',         dial: '+245',  fmt: 'XXX XXXX' },
    { code: 'IO', flag: _f('IO'), name: 'British Indian Ocean',  dial: '+246',  fmt: 'XXX XXXX' },
    { code: 'AC', flag: _f('AC'), name: 'Ascension Island',      dial: '+247',  fmt: 'XXXXX' },
    { code: 'SC', flag: _f('SC'), name: 'Seychelles',            dial: '+248',  fmt: 'X XX XX XX' },
    { code: 'SD', flag: _f('SD'), name: 'السودان (Sudan)',       dial: '+249',  fmt: 'XX XXX XXXX' },
    { code: 'RW', flag: _f('RW'), name: 'Rwanda',                dial: '+250',  fmt: 'XXX XXX XXX' },
    { code: 'ET', flag: _f('ET'), name: 'Ethiopia',               dial: '+251',  fmt: 'XX XXX XXXX' },
    { code: 'SO', flag: _f('SO'), name: 'Soomaaliya',             dial: '+252',  fmt: 'XX XXX XXX' },
    { code: 'DJ', flag: _f('DJ'), name: 'Djibouti',               dial: '+253',  fmt: 'XX XX XX XX' },
    { code: 'KE', flag: _f('KE'), name: 'Kenya',                  dial: '+254',  fmt: 'XXX XXXXXX' },
    { code: 'TZ', flag: _f('TZ'), name: 'Tanzania',               dial: '+255',  fmt: 'XXX XXX XXX' },
    { code: 'UG', flag: _f('UG'), name: 'Uganda',                 dial: '+256',  fmt: 'XXX XXXXXX' },
    { code: 'BI', flag: _f('BI'), name: 'Burundi',                dial: '+257',  fmt: 'XX XX XXXX' },
    { code: 'MZ', flag: _f('MZ'), name: 'Moçambique',            dial: '+258',  fmt: 'XX XXX XXXX' },
    { code: 'ZM', flag: _f('ZM'), name: 'Zambia',                 dial: '+260',  fmt: 'XX XXX XXXX' },
    { code: 'MG', flag: _f('MG'), name: 'Madagascar',             dial: '+261',  fmt: 'XX XX XXX XX' },
    { code: 'RE', flag: _f('RE'), name: 'Réunion',               dial: '+262',  fmt: 'XXX XX XX XX' },
    { code: 'YT', flag: _f('YT'), name: 'Mayotte',                dial: '+262',  fmt: 'XXX XX XX XX' },
    { code: 'ZW', flag: _f('ZW'), name: 'Zimbabwe',               dial: '+263',  fmt: 'XX XXX XXXX' },
    { code: 'NA', flag: _f('NA'), name: 'Namibia',                dial: '+264',  fmt: 'XX XXX XXXX' },
    { code: 'MW', flag: _f('MW'), name: 'Malawi',                 dial: '+265',  fmt: 'X XXXX XXXX' },
    { code: 'LS', flag: _f('LS'), name: 'Lesotho',                dial: '+266',  fmt: 'XXXX XXXX' },
    { code: 'BW', flag: _f('BW'), name: 'Botswana',               dial: '+267',  fmt: 'XX XXX XXX' },
    { code: 'SZ', flag: _f('SZ'), name: 'Eswatini',               dial: '+268',  fmt: 'XXXX XXXX' },
    { code: 'KM', flag: _f('KM'), name: 'Comores',                dial: '+269',  fmt: 'XXX XXXX' },
    { code: 'ZA', flag: _f('ZA'), name: 'South Africa',           dial: '+27',   fmt: 'XX XXX XXXX' },
    { code: 'SH', flag: _f('SH'), name: 'Saint Helena',           dial: '+290',  fmt: 'XXXXX' },
    { code: 'TA', flag: _f('TA'), name: 'Tristan da Cunha',       dial: '+290',  fmt: 'XXXX' },
    { code: 'ER', flag: _f('ER'), name: 'Eritrea',                dial: '+291',  fmt: 'X XXX XXX' },
    { code: 'AW', flag: _f('AW'), name: 'Aruba',                  dial: '+297',  fmt: 'XXX XXXX' },
    { code: 'FO', flag: _f('FO'), name: 'Føroyar',               dial: '+298',  fmt: 'XXXXXX' },
    { code: 'GL', flag: _f('GL'), name: 'Kalaallit Nunaat',        dial: '+299',  fmt: 'XX XX XX' },

    // ── Зона 3: Европа ─────────────────────────────────────────────────
    { code: 'GR', flag: _f('GR'), name: 'Ελλάδα (Greece)',        dial: '+30',   fmt: 'XXX XXX XXXX' },
    { code: 'NL', flag: _f('NL'), name: 'Nederland',               dial: '+31',   fmt: 'X XXXXXXXX' },
    { code: 'BE', flag: _f('BE'), name: 'Belgique',                dial: '+32',   fmt: 'XXX XX XX XX' },
    { code: 'IT', flag: _f('IT'), name: 'Italia',                  dial: '+39',   fmt: 'XXX XXX XXXX' },
    { code: 'ES', flag: _f('ES'), name: 'España',                 dial: '+34',   fmt: 'XXX XXX XXX' },
    { code: 'GI', flag: _f('GI'), name: 'Gibraltar',               dial: '+350',  fmt: 'XXXX XXXX' },
    { code: 'PT', flag: _f('PT'), name: 'Portugal',                dial: '+351',  fmt: 'XXX XXX XXX' },
    { code: 'LU', flag: _f('LU'), name: 'Luxembourg',              dial: '+352',  fmt: 'XXX XXX XXX' },
    { code: 'IE', flag: _f('IE'), name: 'Ireland',                 dial: '+353',  fmt: 'XX XXX XXXX' },
    { code: 'IS', flag: _f('IS'), name: 'Ísland',                 dial: '+354',  fmt: 'XXX XXXX' },
    { code: 'AL', flag: _f('AL'), name: 'Shqipëria',              dial: '+355',  fmt: 'XX XXX XXXX' },
    { code: 'MT', flag: _f('MT'), name: 'Malta',                   dial: '+356',  fmt: 'XXXX XXXX' },
    { code: 'CY', flag: _f('CY'), name: 'Κύπρος (Cyprus)',        dial: '+357',  fmt: 'XX XXXXXX' },
    { code: 'FI', flag: _f('FI'), name: 'Suomi (Finland)',         dial: '+358',  fmt: 'XX XXX XXXX' },
    { code: 'AX', flag: _f('AX'), name: 'Åland Islands',          dial: '+358',  fmt: 'XX XXX XXXX' },
    { code: 'BG', flag: _f('BG'), name: 'България',               dial: '+359',  fmt: 'XX XXX XXXX' },
    { code: 'HU', flag: _f('HU'), name: 'Magyarország',           dial: '+36',   fmt: 'XX XXX XXXX' },
    { code: 'LT', flag: _f('LT'), name: 'Lietuva',                dial: '+370',  fmt: 'XXX XXXXX' },
    { code: 'LV', flag: _f('LV'), name: 'Latvija',                dial: '+371',  fmt: 'XXXX XXXX' },
    { code: 'EE', flag: _f('EE'), name: 'Eesti',                  dial: '+372',  fmt: 'XXXX XXXX' },
    { code: 'MD', flag: _f('MD'), name: 'Moldova',                dial: '+373',  fmt: 'XX XXX XXX' },
    { code: 'AM', flag: _f('AM'), name: 'Հայաստան',               dial: '+374',  fmt: 'XX XXXXXX' },
    { code: 'BY', flag: _f('BY'), name: 'Беларусь',               dial: '+375',  fmt: 'XX XXX XX XX' },
    { code: 'AD', flag: _f('AD'), name: 'Andorra',                dial: '+376',  fmt: 'XXX XXX' },
    { code: 'MC', flag: _f('MC'), name: 'Monaco',                 dial: '+377',  fmt: 'XXXX XXXX' },
    { code: 'SM', flag: _f('SM'), name: 'San Marino',             dial: '+378',  fmt: 'XXXX XXXXXX' },
    { code: 'VA', flag: _f('VA'), name: 'Città del Vaticano',    dial: '+379',  fmt: 'XXXXXXXX' },
    { code: 'RS', flag: _f('RS'), name: 'Србија',                 dial: '+381',  fmt: 'XX XXX XXXX' },
    { code: 'ME', flag: _f('ME'), name: 'Crna Gora',              dial: '+382',  fmt: 'XX XXX XXX' },
    { code: 'XK', flag: _f('XK'), name: 'Kosova',                 dial: '+383',  fmt: 'XX XXX XXX' },
    { code: 'HR', flag: _f('HR'), name: 'Hrvatska',               dial: '+385',  fmt: 'XX XXX XXXX' },
    { code: 'SI', flag: _f('SI'), name: 'Slovenija',              dial: '+386',  fmt: 'XX XXX XXX' },
    { code: 'BA', flag: _f('BA'), name: 'Bosna i Hercegovina',    dial: '+387',  fmt: 'XX XXX XXX' },
    { code: 'MK', flag: _f('MK'), name: 'С.Македонија',           dial: '+389',  fmt: 'XX XXX XXX' },

    // ── Зона 4: Европа ─────────────────────────────────────────────────
    { code: 'RO', flag: _f('RO'), name: 'România',               dial: '+40',   fmt: 'XXX XXX XXX' },
    { code: 'CH', flag: _f('CH'), name: 'Schweiz',                dial: '+41',   fmt: 'XX XXX XX XX' },
    { code: 'CZ', flag: _f('CZ'), name: 'Česko',                 dial: '+420',  fmt: 'XXX XXX XXX' },
    { code: 'SK', flag: _f('SK'), name: 'Slovensko',              dial: '+421',  fmt: 'XXX XXX XXX' },
    { code: 'LI', flag: _f('LI'), name: 'Liechtenstein',          dial: '+423',  fmt: 'XXX XXXX' },
    { code: 'AT', flag: _f('AT'), name: 'Österreich',            dial: '+43',   fmt: 'XXX XXXXXXX' },
    { code: 'GG', flag: _f('GG'), name: 'Guernsey',               dial: '+44',   fmt: 'XXXX XXXXXX' },
    { code: 'JE', flag: _f('JE'), name: 'Jersey',                 dial: '+44',   fmt: 'XXXX XXXXXX' },
    { code: 'IM', flag: _f('IM'), name: 'Isle of Man',             dial: '+44',   fmt: 'XXXX XXXXXX' },
    { code: 'DK', flag: _f('DK'), name: 'Danmark',                dial: '+45',   fmt: 'XX XX XX XX' },
    { code: 'SE', flag: _f('SE'), name: 'Sverige',                dial: '+46',   fmt: 'XX XXX XX XX' },
    { code: 'NO', flag: _f('NO'), name: 'Norge',                  dial: '+47',   fmt: 'XXX XX XXX' },
    { code: 'SJ', flag: _f('SJ'), name: 'Svalbard & Jan Mayen',   dial: '+47',   fmt: 'XX XX XX XX' },
    { code: 'PL', flag: _f('PL'), name: 'Polska',                 dial: '+48',   fmt: 'XXX XXX XXX' },

    // ── Зона 5: Латинская Америка ───────────────────────────────────────
    { code: 'FK', flag: _f('FK'), name: 'Falkland Islands',        dial: '+500',  fmt: 'XXXXX' },
    { code: 'GS', flag: _f('GS'), name: 'South Georgia & S.Sandwich Is.', dial: '+500', fmt: 'XXXXX' },
    { code: 'BZ', flag: _f('BZ'), name: 'Belize',                  dial: '+501',  fmt: 'XXX XXXX' },
    { code: 'GT', flag: _f('GT'), name: 'Guatemala',               dial: '+502',  fmt: 'XXXX XXXX' },
    { code: 'SV', flag: _f('SV'), name: 'El Salvador',             dial: '+503',  fmt: 'XXXX XXXX' },
    { code: 'HN', flag: _f('HN'), name: 'Honduras',                dial: '+504',  fmt: 'XXXX XXXX' },
    { code: 'NI', flag: _f('NI'), name: 'Nicaragua',               dial: '+505',  fmt: 'XXXX XXXX' },
    { code: 'CR', flag: _f('CR'), name: 'Costa Rica',              dial: '+506',  fmt: 'XXXX XXXX' },
    { code: 'PA', flag: _f('PA'), name: 'Panamá',                 dial: '+507',  fmt: 'XXXX XXXX' },
    { code: 'PM', flag: _f('PM'), name: 'Saint-Pierre-et-Miquelon',dial: '+508', fmt: 'XX XX XX' },
    { code: 'HT', flag: _f('HT'), name: 'Haïti',                 dial: '+509',  fmt: 'XX XX XXXX' },
    { code: 'PE', flag: _f('PE'), name: 'Perú',                   dial: '+51',   fmt: 'XXX XXX XXX' },
    { code: 'MX', flag: _f('MX'), name: 'México',                dial: '+52',   fmt: 'XX XXXX XXXX' },
    { code: 'CU', flag: _f('CU'), name: 'Cuba',                   dial: '+53',   fmt: 'X XXX XXXX' },
    { code: 'AR', flag: _f('AR'), name: 'Argentina',               dial: '+54',   fmt: 'XX XXXX XXXX' },
    { code: 'CL', flag: _f('CL'), name: 'Chile',                  dial: '+56',   fmt: 'X XXXX XXXX' },
    { code: 'CO', flag: _f('CO'), name: 'Colombia',               dial: '+57',   fmt: 'XXX XXX XXXX' },
    { code: 'VE', flag: _f('VE'), name: 'Venezuela',              dial: '+58',   fmt: 'XXX XXX XXXX' },
    { code: 'GP', flag: _f('GP'), name: 'Guadeloupe',             dial: '+590',  fmt: 'XXX XX XX XX' },
    { code: 'BL', flag: _f('BL'), name: 'Saint-Barthélemy',      dial: '+590',  fmt: 'XXX XX XX XX' },
    { code: 'MF', flag: _f('MF'), name: 'Saint-Martin',           dial: '+590',  fmt: 'XXX XX XX XX' },
    { code: 'BO', flag: _f('BO'), name: 'Bolivia',                dial: '+591',  fmt: 'X XXX XXXX' },
    { code: 'GY', flag: _f('GY'), name: 'Guyana',                 dial: '+592',  fmt: 'XXX XXXX' },
    { code: 'EC', flag: _f('EC'), name: 'Ecuador',                dial: '+593',  fmt: 'XX XXX XXXX' },
    { code: 'GF', flag: _f('GF'), name: 'Guyane française',      dial: '+594',  fmt: 'XXX XX XX XX' },
    { code: 'PY', flag: _f('PY'), name: 'Paraguay',               dial: '+595',  fmt: 'XXX XXX XXX' },
    { code: 'MQ', flag: _f('MQ'), name: 'Martinique',             dial: '+596',  fmt: 'XXX XX XX XX' },
    { code: 'SR', flag: _f('SR'), name: 'Suriname',               dial: '+597',  fmt: 'XXX XXXX' },
    { code: 'UY', flag: _f('UY'), name: 'Uruguay',                dial: '+598',  fmt: 'X XXX XXXX' },
    { code: 'BQ', flag: _f('BQ'), name: 'Caribbean Netherlands',  dial: '+599',  fmt: 'XXX XXXX' },
    { code: 'CW', flag: _f('CW'), name: 'Curaçao',              dial: '+5999', fmt: 'XXX XXXX' },

    // ── Зона 6: Юго-Вост. Азия и Океания ────────────────────────────────
    { code: 'MY', flag: _f('MY'), name: 'Malaysia',               dial: '+60',   fmt: 'XX XXXX XXXX' },
    { code: 'AU', flag: _f('AU'), name: 'Australia',              dial: '+61',   fmt: 'XXX XXX XXX' },
    { code: 'CX', flag: _f('CX'), name: 'Christmas Island',       dial: '+61',   fmt: 'XXX XXX XXX' },
    { code: 'CC', flag: _f('CC'), name: 'Cocos (Keeling) Islands', dial: '+61',   fmt: 'XXX XXX XXX' },
    { code: 'ID', flag: _f('ID'), name: 'Indonesia',              dial: '+62',   fmt: 'XXX XXXX XXXX' },
    { code: 'PH', flag: _f('PH'), name: 'Philippines',            dial: '+63',   fmt: 'XXX XXX XXXX' },
    { code: 'NZ', flag: _f('NZ'), name: 'New Zealand',            dial: '+64',   fmt: 'XX XXX XXXX' },
    { code: 'SG', flag: _f('SG'), name: 'Singapore',              dial: '+65',   fmt: 'XXXX XXXX' },
    { code: 'TH', flag: _f('TH'), name: 'ไทย (Thailand)',         dial: '+66',   fmt: 'XX XXX XXXX' },
    { code: 'TL', flag: _f('TL'), name: 'Timor-Leste',            dial: '+670',  fmt: 'XXXX XXXX' },
    { code: 'NF', flag: _f('NF'), name: 'Norfolk Island',          dial: '+672',  fmt: 'XX XXXX' },
    { code: 'BN', flag: _f('BN'), name: 'Brunei',                  dial: '+673',  fmt: 'XXX XXXX' },
    { code: 'NR', flag: _f('NR'), name: 'Nauru',                   dial: '+674',  fmt: 'XXX XXXX' },
    { code: 'PG', flag: _f('PG'), name: 'Papua New Guinea',        dial: '+675',  fmt: 'XXX XXXX' },
    { code: 'TO', flag: _f('TO'), name: 'Tonga',                   dial: '+676',  fmt: 'XXX XXXX' },
    { code: 'SB', flag: _f('SB'), name: 'Solomon Islands',         dial: '+677',  fmt: 'XX XXXXX' },
    { code: 'VU', flag: _f('VU'), name: 'Vanuatu',                 dial: '+678',  fmt: 'XX XXXXX' },
    { code: 'FJ', flag: _f('FJ'), name: 'Fiji',                    dial: '+679',  fmt: 'XXX XXXX' },
    { code: 'PW', flag: _f('PW'), name: 'Palau',                   dial: '+680',  fmt: 'XXX XXXX' },
    { code: 'WF', flag: _f('WF'), name: 'Wallis et Futuna',        dial: '+681',  fmt: 'XX XX XX' },
    { code: 'CK', flag: _f('CK'), name: 'Cook Islands',            dial: '+682',  fmt: 'XX XXX' },
    { code: 'NU', flag: _f('NU'), name: 'Niue',                    dial: '+683',  fmt: 'XXXX' },
    { code: 'WS', flag: _f('WS'), name: 'Samoa',                   dial: '+685',  fmt: 'XX XXXXX' },
    { code: 'KI', flag: _f('KI'), name: 'Kiribati',                dial: '+686',  fmt: 'XXXX XXXX' },
    { code: 'NC', flag: _f('NC'), name: 'Nouvelle-Calédonie',     dial: '+687',  fmt: 'XX XX XX' },
    { code: 'TV', flag: _f('TV'), name: 'Tuvalu',                  dial: '+688',  fmt: 'XX XXXX' },
    { code: 'PF', flag: _f('PF'), name: 'Polynésie française',   dial: '+689',  fmt: 'XX XX XX XX' },
    { code: 'TK', flag: _f('TK'), name: 'Tokelau',                 dial: '+690',  fmt: 'XXXX' },
    { code: 'FM', flag: _f('FM'), name: 'Micronesia',              dial: '+691',  fmt: 'XXX XXXX' },
    { code: 'MH', flag: _f('MH'), name: 'Marshall Islands',        dial: '+692',  fmt: 'XXX XXXX' },

    // ── Зона 7: Россия & Казахстан (уже вверху) ─────────────────────────

    // ── Зона 8: Восточная и Юго-Восточная Азия ──────────────────────────
    { code: 'JP', flag: _f('JP'), name: '日本 (Japan)',            dial: '+81',   fmt: 'XX XXXX XXXX' },
    { code: 'KR', flag: _f('KR'), name: '한국 (South Korea)',     dial: '+82',   fmt: 'XX XXXX XXXX' },
    { code: 'VN', flag: _f('VN'), name: 'Việt Nam',              dial: '+84',   fmt: 'XXX XXX XXXX' },
    { code: 'KP', flag: _f('KP'), name: '조선 (North Korea)',     dial: '+850',  fmt: 'XXX XXX XXXX' },
    { code: 'HK', flag: _f('HK'), name: '香港 (Hong Kong)',       dial: '+852',  fmt: 'XXXX XXXX' },
    { code: 'MO', flag: _f('MO'), name: '澳門 (Macau)',          dial: '+853',  fmt: 'XXXX XXXX' },
    { code: 'KH', flag: _f('KH'), name: 'កម្ពុជា (Cambodia)',    dial: '+855',  fmt: 'XX XXX XXXX' },
    { code: 'LA', flag: _f('LA'), name: 'ລາວ (Laos)',            dial: '+856',  fmt: 'XX XX XXX XXX' },
    { code: 'BD', flag: _f('BD'), name: 'বাংলাদেশ (Bangladesh)', dial: '+880',  fmt: 'XXXX XXXXXX' },
    { code: 'TW', flag: _f('TW'), name: '台灣 (Taiwan)',          dial: '+886',  fmt: 'XXX XXX XXX' },

    // ── Зона 9: Зап., Центр. и Южная Азия ───────────────────────────────
    { code: 'TR', flag: _f('TR'), name: 'Türkiye',               dial: '+90',   fmt: 'XXX XXX XXXX' },
    { code: 'PK', flag: _f('PK'), name: 'پاکستان (Pakistan)',    dial: '+92',   fmt: 'XXX XXX XXXX' },
    { code: 'AF', flag: _f('AF'), name: 'افغانستان (Afghanistan)',dial: '+93',   fmt: 'XX XXX XXXX' },
    { code: 'LK', flag: _f('LK'), name: 'Sri Lanka',              dial: '+94',   fmt: 'XX XXX XXXX' },
    { code: 'MM', flag: _f('MM'), name: 'Myanmar',                dial: '+95',   fmt: 'XX XXX XXXX' },
    { code: 'MV', flag: _f('MV'), name: 'Maldives',               dial: '+960',  fmt: 'XXX XXXX' },
    { code: 'LB', flag: _f('LB'), name: 'لبنان (Lebanon)',       dial: '+961',  fmt: 'XX XXX XXX' },
    { code: 'JO', flag: _f('JO'), name: 'الأردن (Jordan)',       dial: '+962',  fmt: 'X XXXX XXXX' },
    { code: 'SY', flag: _f('SY'), name: 'سوريا (Syria)',         dial: '+963',  fmt: 'XXX XXX XXX' },
    { code: 'IQ', flag: _f('IQ'), name: 'العراق (Iraq)',         dial: '+964',  fmt: 'XXX XXX XXXX' },
    { code: 'KW', flag: _f('KW'), name: 'الكويت (Kuwait)',       dial: '+965',  fmt: 'XXXX XXXX' },
    { code: 'SA', flag: _f('SA'), name: 'السعودية',              dial: '+966',  fmt: 'XX XXX XXXX' },
    { code: 'YE', flag: _f('YE'), name: 'اليمن (Yemen)',         dial: '+967',  fmt: 'XXX XXX XXX' },
    { code: 'OM', flag: _f('OM'), name: 'عُمان (Oman)',          dial: '+968',  fmt: 'XXXX XXXX' },
    { code: 'PS', flag: _f('PS'), name: 'فلسطين (Palestine)',    dial: '+970',  fmt: 'XX XXX XXXX' },
    { code: 'AE', flag: _f('AE'), name: 'الإمارات (UAE)',        dial: '+971',  fmt: 'XX XXX XXXX' },
    { code: 'IL', flag: _f('IL'), name: 'ישראל (Israel)',        dial: '+972',  fmt: 'XX XXX XXXX' },
    { code: 'BH', flag: _f('BH'), name: 'البحرين (Bahrain)',     dial: '+973',  fmt: 'XXXX XXXX' },
    { code: 'QA', flag: _f('QA'), name: 'قطر (Qatar)',            dial: '+974',  fmt: 'XXXX XXXX' },
    { code: 'BT', flag: _f('BT'), name: 'Bhutan',                 dial: '+975',  fmt: 'XX XXX XXX' },
    { code: 'MN', flag: _f('MN'), name: 'Монгол Улс',             dial: '+976',  fmt: 'XXXX XXXX' },
    { code: 'NP', flag: _f('NP'), name: 'नेपाल (Nepal)',         dial: '+977',  fmt: 'XX XXXX XXXX' },
    { code: 'IR', flag: _f('IR'), name: 'ایران (Iran)',           dial: '+98',   fmt: 'XXX XXX XXXX' },
    { code: 'TJ', flag: _f('TJ'), name: 'Тоҷикистон',            dial: '+992',  fmt: 'XX XXX XXXX' },
    { code: 'TM', flag: _f('TM'), name: 'Türkmenistan',          dial: '+993',  fmt: 'XX XXXXXX' },
    { code: 'AZ', flag: _f('AZ'), name: 'Azərbaycan',            dial: '+994',  fmt: 'XX XXX XX XX' },
    { code: 'GE', flag: _f('GE'), name: 'საქართველო',            dial: '+995',  fmt: 'XXX XX XX XX' },
    { code: 'KG', flag: _f('KG'), name: 'Кыргызстан',             dial: '+996',  fmt: 'XXX XXXXXX' },
    { code: 'UZ', flag: _f('UZ'), name: 'Oʻzbekiston',           dial: '+998',  fmt: 'XX XXX XX XX' },
];

let _selectedCountry = COUNTRIES[0]; // RU default
let _dropdownBuilt = false;

// ============================================================================
// PASSWORD STRENGTH
// ============================================================================
const PW_LABELS = [
    '',
    window.t ? window.t('password.veryWeak') : 'Very weak',
    window.t ? window.t('password.weak') : 'Weak',
    window.t ? window.t('password.medium') : 'Medium',
    window.t ? window.t('password.good') : 'Good',
    window.t ? window.t('password.excellent') : 'Excellent',
];

function _calcStrength(pw) {
    if (!pw) return { level: 0, score: 0 };
    let score = 0;
    const has = {
        len:     pw.length >= 8,
        upper:   /[A-Z\u0410-\u042F]/.test(pw),
        lower:   /[a-z\u0430-\u044F]/.test(pw),
        digit:   /\d/.test(pw),
        special: /[^A-Za-z0-9\u0410-\u044F\u0430-\u044F]/.test(pw),
    };
    if (has.len)     score++;
    if (has.upper)   score++;
    if (has.lower)   score++;
    if (has.digit)   score++;
    if (has.special) score++;
    // Bonus for length
    if (pw.length >= 12) score = Math.max(score, 3);
    if (pw.length >= 16) score = Math.max(score, 4);
    // Cap
    const level = Math.min(5, Math.max(1, score));
    return { level, has };
}

function _updateStrengthUI(pw) {
    const wrap = $('r-pass-strength');
    if (!wrap) return;

    if (!pw) {
        wrap.classList.remove('visible');
        return;
    }
    wrap.classList.add('visible');

    const { level, has } = _calcStrength(pw);

    const fill = $('pw-bar-fill');
    const label = $('pw-label');
    const details = $('pw-details');

    if (fill) fill.setAttribute('data-level', level);
    if (label) {
        label.textContent = PW_LABELS[level];
        label.setAttribute('data-level', level);
    }
    if (details) {
        const entropy = Math.round(pw.length * Math.log2(
            (has.lower ? 26 : 0) + (has.upper ? 26 : 0) +
            (has.digit ? 10 : 0) + (has.special ? 32 : 0) || 1
        ));
        details.textContent = '~' + entropy + ' bit';
    }

    // Criteria badges
    const checks = { len: has.len, upper: has.upper, lower: has.lower, digit: has.digit, special: has.special };
    for (const [key, pass] of Object.entries(checks)) {
        const el = $('pw-' + key);
        if (el) el.classList.toggle('pass', pass);
    }
}

// ============================================================================
// PASSWORD CONFIRMATION
// ============================================================================
function _updateMatchUI() {
    const pw = $('r-pass')?.value || '';
    const confirm = $('r-pass-confirm')?.value || '';
    const status = $('pw-match-status');
    if (!status) return;

    if (!confirm) {
        status.textContent = '';
        status.className = 'pw-match-status';
        return;
    }
    if (pw === confirm) {
        status.textContent = '\u2713 ' + (window.t ? window.t('password.match') : 'Passwords match');
        status.className = 'pw-match-status match';
    } else {
        status.textContent = '\u2717 ' + (window.t ? window.t('password.mismatch') : 'Passwords do not match');
        status.className = 'pw-match-status mismatch';
    }
}

// ============================================================================
// PHONE NUMBER FORMATTING
// ============================================================================
function _formatPhone(digits, fmt) {
    let result = '';
    let di = 0;
    for (let i = 0; i < fmt.length && di < digits.length; i++) {
        if (fmt[i] === 'X') {
            result += digits[di++];
        } else {
            result += fmt[i];
        }
    }
    // Append remaining digits beyond the format
    if (di < digits.length) {
        result += digits.slice(di);
    }
    return result;
}

function _onPhoneInput() {
    const input = $('r-phone');
    if (!input) return;
    const raw = input.value.replace(/\D/g, '');
    const formatted = _formatPhone(raw, _selectedCountry.fmt);
    if (input.value !== formatted) {
        const pos = input.selectionStart;
        const diff = formatted.length - input.value.length;
        input.value = formatted;
        input.setSelectionRange(pos + diff, pos + diff);
    }
}

// ============================================================================
// COUNTRY DROPDOWN
// ============================================================================
function _buildDropdown() {
    const dd = $('phone-country-dropdown');
    if (!dd || _dropdownBuilt) return;
    _dropdownBuilt = true;

    const search = document.createElement('input');
    search.type = 'text';
    search.className = 'phone-country-search';
    search.placeholder = window.t ? window.t('phone.searchCountry') : 'Search country...';
    search.autocomplete = 'off';
    dd.appendChild(search);

    const list = document.createElement('div');
    list.className = 'phone-country-list';
    dd.appendChild(list);

    function render(filter) {
        while (list.firstChild) list.removeChild(list.firstChild);
        const lf = (filter || '').toLowerCase();
        const filtered = lf
            ? COUNTRIES.filter(c =>
                c.name.toLowerCase().includes(lf) ||
                c.dial.includes(lf) ||
                c.code.toLowerCase().includes(lf))
            : COUNTRIES;

        for (const c of filtered) {
            const row = document.createElement('div');
            row.className = 'phone-country-item';
            row.setAttribute('role', 'option');

            const flag = document.createElement('span');
            flag.className = 'pc-flag';
            flag.textContent = c.flag;

            const name = document.createElement('span');
            name.className = 'pc-name';
            name.textContent = c.name;

            const code = document.createElement('span');
            code.className = 'pc-code';
            code.textContent = c.dial;

            row.appendChild(flag);
            row.appendChild(name);
            row.appendChild(code);

            row.addEventListener('click', () => {
                _selectCountry(c);
                dd.classList.remove('open');
                search.value = '';
                render('');
            });
            list.appendChild(row);
        }
    }

    search.addEventListener('input', () => render(search.value));
    render('');
}

function _selectCountry(c) {
    _selectedCountry = c;
    const flagEl = $('phone-flag');
    const codeEl = $('phone-code');
    if (flagEl) flagEl.textContent = c.flag;
    if (codeEl) codeEl.textContent = c.dial;
    // Re-format current value
    _onPhoneInput();
    // Update placeholder
    const input = $('r-phone');
    if (input) input.placeholder = _formatPhone('9'.repeat(10), c.fmt);
}

export function toggleCountryDropdown() {
    const dd = $('phone-country-dropdown');
    if (!dd) return;
    _buildDropdown();
    const isOpen = dd.classList.toggle('open');
    if (isOpen) {
        const search = dd.querySelector('.phone-country-search');
        if (search) setTimeout(() => search.focus(), 50);
    }
}

// Close dropdown on outside click
function _onDocClick(e) {
    const dd = $('phone-country-dropdown');
    const btn = $('phone-country-btn');
    if (!dd || !dd.classList.contains('open')) return;
    if (dd.contains(e.target) || (btn && btn.contains(e.target))) return;
    dd.classList.remove('open');
}

// ============================================================================
// GET FULL PHONE (for doRegister)
// ============================================================================
export function getFullPhone() {
    const input = $('r-phone');
    if (!input) return '';
    const digits = input.value.replace(/\D/g, '');
    if (!digits) return '';
    return _selectedCountry.dial + digits;
}

// ============================================================================
// PASSWORD VALIDATION (for doRegister)
// ============================================================================
export function validatePasswords() {
    const pw = $('r-pass')?.value || '';
    const confirm = $('r-pass-confirm')?.value || '';
    if (pw !== confirm) {
        return window.t ? window.t('password.mismatch') : 'Passwords do not match';
    }
    return null;
}

// ============================================================================
// INIT
// ============================================================================
export function initPhonePassword() {
    // Password strength
    const passInput = $('r-pass');
    if (passInput) {
        passInput.addEventListener('input', () => {
            _updateStrengthUI(passInput.value);
            _updateMatchUI();
        });
    }

    // Password confirm
    const confirmInput = $('r-pass-confirm');
    if (confirmInput) {
        confirmInput.addEventListener('input', _updateMatchUI);
    }

    // Phone formatting
    const phoneInput = $('r-phone');
    if (phoneInput) {
        phoneInput.addEventListener('input', _onPhoneInput);
    }

    // Close dropdown on outside click
    document.addEventListener('click', _onDocClick);
}
