rule stratum {
  meta:
    description = "Used for detection potential new mining pool"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50
    data = "2018-03-03"

  strings:
    $stratum = /.............................................xmr-asia1.nanopool.org............................................................/

  condition:
    all of them
}
