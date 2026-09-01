# Mule Account Layering Trace (Simulated)

> Wallet address and account identifiers are fictional/simulated.

## Hop-by-hop flow

```
Victim Account
   │  INR 48,500.00 (TXN SIM-000217)
   ▼
Mule Account A  [email protected]   (opened 6 days prior, no prior txn history)
   │
   ├── 60% → Mule Account B  [email protected]   (INR 29,100.00)
   └── 40% → Mule Account C  [email protected]   (INR 19,400.00)
                    │
                    ▼
          P2P Crypto Exchange Order #EX-88213
                    │  INR → USDT (stablecoin)
                    ▼
          Wallet: bc1q-SIMULATED-0001-EXAMPLE
```

## Red flags identified

1. **New-account receipt** — Mule Account A had no prior transaction
   history before receiving the full stolen amount, a strong indicator
   it was recruited/rented specifically for this scheme.
2. **Rapid multi-way split ("smurfing")** — funds were split into two
   sub-threshold transfers within 2 hours of receipt, a pattern used to
   stay under automated Suspicious Transaction Report (STR) thresholds.
3. **Crypto conversion at the terminal hop** — converting INR to a
   stablecoin at the final hop is a common technique to frustrate
   further fiat-currency tracing, since it moves the trail onto a
   public blockchain that requires different tooling to follow.
4. **Off-hours timing** — the initial fraudulent transaction occurred at
   03:47 IST, outside the victim's normal activity pattern per the
   transaction log.

## Recommended tracing method (real-world)

- Request Suspicious Transaction Reports (STRs) and KYC documents for
  Mule Accounts A/B/C from the bank's compliance desk / FIU-IND.
- Use a public block explorer to follow the wallet's on-chain graph and
  check whether the receiving address clusters with a known exchange's
  published hot-wallet addresses (many exchanges' deposit addresses are
  identifiable this way, which can identify the cash-out point).
- Correlate the malware C2 beacon timestamps (`evidence/malware/`) with
  the transaction timestamps above to build one unified attack timeline.
