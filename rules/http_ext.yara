rule stratum {
  meta:
    description = "Used for detection potential new mining pool"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50
    data = "2018-03-03"

  strings:
    $stratum = /https{0,1}\:\/\/[a-zA-Z0-9\.\:\/\-\_\~]{10,100}\.(exe|dll|zip|sct|gz|sh|7z)/ nocase

  condition:
    all of them
}
