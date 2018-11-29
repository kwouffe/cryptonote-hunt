rule hardcoded_quazar_wallet {
  meta:
    description = "Detecting hardcoded quazarcoin wallet address"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $wallet = /1[0-9a-zA-Z]{94}/

  condition:
    all of them
}
