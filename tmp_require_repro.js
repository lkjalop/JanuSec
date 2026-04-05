try{
  require('./tmp_playwright_check_buttons.js');
  console.log('repro required');
}catch(e){
  console.error('REPRO_REQUIRE_ERROR:');
  console.error(e && e.stack ? e.stack : e);
  process.exit(1);
}
