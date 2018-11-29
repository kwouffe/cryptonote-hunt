rule base64 {
  meta:
    description = "Detecting use of fuckups"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $gfas = /hello[0-9]/

  condition:
    any of them
}
