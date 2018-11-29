rule test {
  strings:
      $test = /Net\.WebClient\)\.DownloadFile\(.*/ nocase

  condition:
      any of them
  }
