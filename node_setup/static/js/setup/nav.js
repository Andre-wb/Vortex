// node_setup/static/js/setup/nav.js — навигация по шагам мастера

/**
 * Переключает на указанный шаг (только если n <= текущий шаг).
 * @param {number} n - номер шага (1–6)
 */
function goStep(n) {
    if (n > state.step) return;
    _setStep(n);
}

/**
 * Внутренняя функция: активирует шаг с номером n, обновляет индикаторы шагов.
 * @param {number} n
 */
function _setStep(n) {
    document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
    document.getElementById('step-' + n).classList.add('active');

    // Обновляем кружки и линии в шапке (stepbar)
    for (let i = 1; i <= 6; i++) {
        const dot  = document.getElementById('sdot-' + i);
        const line = document.getElementById('sline-' + i);
        dot.classList.remove('active', 'done');
        if (line) line.classList.remove('done');
        if (i < n)  { dot.classList.add('done');   if (line) line.classList.add('done'); }
        if (i === n) { dot.classList.add('active'); }
    }

    state.step = n;
    window.scrollTo({ top: 0, behavior: 'smooth' });
}
