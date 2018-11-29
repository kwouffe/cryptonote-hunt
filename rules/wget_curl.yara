rule wget_curl {
  strings:
      $wget = /wget.{1,100}http.{1,2}\/\/.*/
      $curl = /curl.{1,100}http.{1,2}\/\/.*/

  condition:
      any of them
  }
