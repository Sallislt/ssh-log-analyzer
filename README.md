# SSH Log Analyzer (Python)

🇫🇷 Petit outil de détection, dans l’esprit d’un analyste SOC de niveau 1 : il lit les journaux
d’authentification SSH d’un serveur Linux et signale les comportements suspects.

🇬🇧 *A small SOC-style detection tool: parses SSH authentication logs and flags brute force, password spraying and successful logins after repeated failures.*

## Règles de détection

| Règle | Sévérité | Déclencheur (par défaut) |
|---|---|---|
| `brute_force` | haute | ≥ 5 échecs depuis une même IP en 10 minutes (fenêtre glissante) |
| `password_spraying` | moyenne | ≥ 3 noms d’utilisateur différents essayés depuis une même IP |
| `success_after_failures` | haute | connexion réussie depuis une IP qui a échoué au moins 3 fois avant — compte possiblement compromis |

Formats pris en charge : syslog classique (`Oct 23 08:12:03`, Debian/Ubuntu `auth.log`, RHEL `secure`)
et horodatage ISO 8601 ; adresses IPv4 et IPv6.

## Utilisation

```bash
python ssh_log_analyzer.py samples/auth.log
python ssh_log_analyzer.py /var/log/auth.log --threshold 10 --window 5
journalctl -u ssh -o short | python ssh_log_analyzer.py - --json
```

Sortie sur le fichier d’exemple :

```
Failed logins     : 11
Successful logins : 3
Unique source IPs : 3

Findings (3):
  [HIGH  ] brute_force             203.0.113.45     6 failed logins within 10 min
  [HIGH  ] success_after_failures  198.51.100.7     login as 'backup' (password) after 4 failures
  [MEDIUM] password_spraying       203.0.113.45     3 different usernames tried
```

Code retour `2` si une alerte haute est détectée : utilisable dans un script ou une tâche planifiée.
L’option `--json` produit un format exploitable par un SIEM.

## Tests

```bash
python -m unittest -v
```

12 tests : analyse des lignes (syslog, ISO 8601, IPv6, jour à un chiffre), règles de détection,
respect de la fenêtre de temps, sortie JSON et code retour.

## Pistes d’amélioration

- correspondance avec les techniques MITRE ATT&CK (T1110 Brute Force) ;
- enrichissement des IP (géolocalisation, listes de réputation) ;
- export vers Splunk / Elastic.

Python 3.10+, bibliothèque standard uniquement. Les IP d’exemple proviennent des plages réservées à la documentation (RFC 5737 / RFC 3849).

---

Développé avec l’aide d’un assistant IA, dans le cadre de ma reconversion vers la cybersécurité. · Licence MIT
