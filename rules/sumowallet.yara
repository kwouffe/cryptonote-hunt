rule hardcoded_sumo_wallet {
  meta:
    description = "Detecting hardcoded Sumokoin wallet address"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $wallet = /Sumoo[0-9a-zA-Z]{94}/

  condition:
    all of them
}
