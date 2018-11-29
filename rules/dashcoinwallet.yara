rule hardcoded_dashcoin_wallet {
  meta:
    description = "Detecting hardcoded dashcoin wallet address"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $wallet = /D[0-9a-zA-Z]{94}/

  condition:
    all of them
}
