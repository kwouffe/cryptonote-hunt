rule stratum {
  meta:
    description = "Used for detection potential new mining pool"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50
    data = "2018-03-03"

  strings:
    $stratum = /stratum\+tcp:\/\/.{1,25}:[0-9]{1,5}/

  condition:
    all of them
}
