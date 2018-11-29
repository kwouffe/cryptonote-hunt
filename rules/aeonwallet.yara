rule hardcoded_aeon_wallet {
  meta:
    description = "Detecting hardcoded Aeon wallet address"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $wallet = /Wm[st]{1}[0-9a-zA-Z]{94}/

  condition:
    all of them
}
