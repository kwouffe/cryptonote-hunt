rule xmrig {
  meta:
    description = "Detecting use of XMRIG"
    author = "Emilien Le Jamtel - CERT-EU"
    score = 50

  strings:
    $donation_address = "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD" fullword ascii
    $donation_domain = "fee.xmrig.com" fullword ascii
    $usage = "xmrig [OPTIONS]" fullword ascii

  condition:
    any of them
}
