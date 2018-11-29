rule hardcoded_fantom_wallet {
  meta:
    description = "Detecting hardcoded fantomcoin wallet address"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $wallet = /6[0-9a-zA-Z]{94}/

  condition:
    all of them
}
