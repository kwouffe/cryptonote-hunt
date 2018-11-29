rule PowerShell_url_param {
  strings:
      $test = /\$.{1,10}\ =\ "http.*"/ nocase

  condition:
      any of them
  }
