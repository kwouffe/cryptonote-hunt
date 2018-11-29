rule hardcoded_monero_wallet {
  meta:
    description = "Detecting hardcoded monero wallet address"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $wallet = /4[0-9AB][0-9a-zA-Z]{93}|4[0-9AB][0-9a-zA-Z]{104}/
    $test = "4BrL51JCc9NGQ71kWhnYoDRffsDZy7m1HUU7MRU4nUMXAHNFBEJhkTZV9HdaL4gfuNBxLPc3BeMkLGaPbF5vWtANQmm4F1aSTkzJkmZqbi"

  condition:
    any of them
}
