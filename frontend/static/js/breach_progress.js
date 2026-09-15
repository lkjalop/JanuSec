(function () {
  'use strict';

  var timers = {};

  function key(scope, aid) {
    return 'breach.' + scope + '.' + String(aid || 'unknown');
  }

  function schedule(scope, aid, fn, delayMs) {
    var name = key(scope, aid);
    clear(name);
    var timer = window.setTimeout(function () {
      delete timers[name];
      fn();
    }, delayMs || 0);
    timers[name] = timer;
    return timer;
  }

  function scheduleIfMissing(scope, aid, fn, delayMs) {
    var name = key(scope, aid);
    if (timers[name]) return timers[name];
    return schedule(scope, aid, fn, delayMs);
  }

  function clear(nameOrScope, aid) {
    var name = aid === undefined ? nameOrScope : key(nameOrScope, aid);
    var timer = timers[name];
    if (timer) {
      window.clearTimeout(timer);
      delete timers[name];
    }
  }

  function clearAll() {
    Object.keys(timers).forEach(function (name) {
      clear(name);
    });
  }

  window.addEventListener('pagehide', clearAll);
  window.addEventListener('beforeunload', clearAll);

  window.JanuSecBreachProgress = {
    schedule: schedule,
    scheduleIfMissing: scheduleIfMissing,
    clear: clear,
    clearAll: clearAll,
    key: key
  };
}());
