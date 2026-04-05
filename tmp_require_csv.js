try{
  require('./frontend/static/js/csv_analyzer.js');
  console.log('OK: required');
} catch(e){
  console.error('REQUIRE_ERROR');
  console.error(e && e.stack ? e.stack : String(e));
  process.exit(1);
}
