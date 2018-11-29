rule hardcoded_Bytecoin_wallet {
  meta:
    description = "Detecting hardcoded Bytecoin wallet address"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $wallet = /2[0-9AB][0-9a-zA-Z]{93}/

  condition:
    all of them
}
