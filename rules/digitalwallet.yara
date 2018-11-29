rule hardcoded_digitalnote_wallet {
  meta:
    description = "Detecting hardcoded DigitalNote wallet address"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $wallet = /dd[a-z][0-9a-zA-Z]{94}/

  condition:
    all of them
}
