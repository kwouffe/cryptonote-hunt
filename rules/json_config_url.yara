rule monero_json_config {
  meta:
    description = "Used for detection potential new mining pool"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50
    data = "2018-03-03"

  strings:
    $url = /\"url\":\ {0,1}\".*\"/

  condition:
    all of them
}
