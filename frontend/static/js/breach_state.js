(function () {
  'use strict';

  var params = new URLSearchParams(window.location.search);
  window.JanuSecBreachState = window.JanuSecBreachState || {
    params: params,
    AID: params.get('assessment') || '',
    CID: params.get('cluster') || '',
    TAB: params.get('tab') || '',
    state: {
      assessment: null,
      clusters: [],
      rows: [],
      prefillStatus: {},
      execSummary: null
    },
    asyncRedirecting: {},
    asyncPollTimers: {}
  };
})();
