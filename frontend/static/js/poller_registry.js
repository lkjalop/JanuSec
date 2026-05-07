(function () {
  'use strict';

  if (window.JanuSecPollers) return;

  var timers = {};

  function clear(name) {
    try {
      var timer = timers[name];
      if (!timer) return;
      if (timer.kind === 'timeout') clearTimeout(timer.id);
      else clearInterval(timer.id);
      delete timers[name];
    } catch (_) {}
  }

  function setIntervalManaged(name, fn, ms) {
    clear(name);
    timers[name] = { id: setInterval(fn, ms), kind: 'interval' };
    return timers[name].id;
  }

  function setTimeoutManaged(name, fn, ms) {
    clear(name);
    timers[name] = { id: setTimeout(function () {
      clear(name);
      fn();
    }, ms), kind: 'timeout' };
    return timers[name].id;
  }

  function clearAll() {
    Object.keys(timers).forEach(clear);
  }

  window.JanuSecPollers = {
    clear: clear,
    clearAll: clearAll,
    setInterval: setIntervalManaged,
    setTimeout: setTimeoutManaged
  };

  window.addEventListener('pagehide', clearAll);
  window.addEventListener('beforeunload', clearAll);
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') clearAll();
  });
})();
