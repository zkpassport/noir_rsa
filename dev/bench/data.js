window.BENCHMARK_DATA = {
  "lastUpdate": 1789376127721,
  "repoUrl": "https://github.com/zkpassport/noir_rsa",
  "entries": {
    "ACIR Opcodes": [
      {
        "commit": {
          "author": {
            "email": "saleel@saleel.xyz",
            "name": "saleel",
            "username": "saleel"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "900e361e8c6bf7761e0a69ee65067b3274790d03",
          "message": "Merge pull request #12 from zkpassport/as/bump-workflows\n\nchore: Bump the workflows",
          "timestamp": "2026-09-11T13:17:13+04:00",
          "tree_id": "8b4f91577c8146eaa67d6e2fc6fc2608f5e1302d",
          "url": "https://github.com/zkpassport/noir_rsa/commit/900e361e8c6bf7761e0a69ee65067b3274790d03"
        },
        "date": 1789118256016,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "test_verify_sha256_pkcs1v15_2048.json/main",
            "value": 3262,
            "unit": "acir_opcodes"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "75146596+Sarkoxed@users.noreply.github.com",
            "name": "Sarkoxed",
            "username": "Sarkoxed"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5f8bf3a8b52924bf479acf3a6f70ed2d204504e5",
          "message": "Merge pull request #6 from zkpassport/as/noir-rsa-refactoring\n\nchore: Split rsa.nr into modules (no behavior change)",
          "timestamp": "2026-09-14T11:34:35+03:00",
          "tree_id": "5d6142d20c197b5d4390b5024c7d44c5de0fcc82",
          "url": "https://github.com/zkpassport/noir_rsa/commit/5f8bf3a8b52924bf479acf3a6f70ed2d204504e5"
        },
        "date": 1789374937238,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "exponentiate.json/main",
            "value": 24908,
            "unit": "acir_opcodes"
          },
          {
            "name": "exponentiate_const.json/main",
            "value": 2843,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048.json/main",
            "value": 25414,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048_const.json/main",
            "value": 3349,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pss_2048.json/main",
            "value": 26243,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pss_2048_const.json/main",
            "value": 4178,
            "unit": "acir_opcodes"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "75146596+Sarkoxed@users.noreply.github.com",
            "name": "Sarkoxed",
            "username": "Sarkoxed"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9adeac2ad1779f0958c1880a443bb33e71fc826a",
          "message": "Merge pull request #14 from zkpassport/as/exponentiation-optimization\n\nchore: optimize exponentiate_signature and add tests (mirror)",
          "timestamp": "2026-09-14T11:52:49+03:00",
          "tree_id": "8cd329372dd5a82e4582f2e64dcd32d410345d77",
          "url": "https://github.com/zkpassport/noir_rsa/commit/9adeac2ad1779f0958c1880a443bb33e71fc826a"
        },
        "date": 1789375995278,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "exponentiate.json/main",
            "value": 13625,
            "unit": "acir_opcodes"
          },
          {
            "name": "exponentiate_const.json/main",
            "value": 2702,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048.json/main",
            "value": 14131,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048_const.json/main",
            "value": 3208,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pss_2048.json/main",
            "value": 14960,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pss_2048_const.json/main",
            "value": 4037,
            "unit": "acir_opcodes"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "75146596+Sarkoxed@users.noreply.github.com",
            "name": "Sarkoxed",
            "username": "Sarkoxed"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3a8b14a322ab6d3772850cce2a98583f5aaf2184",
          "message": "Merge pull request #15 from zkpassport/as/mgf1-refactoring\n\nchore: generalize mgf1 over the hash function",
          "timestamp": "2026-09-14T11:54:48+03:00",
          "tree_id": "7e71262ccf7da349d570083d3d3316a4918407a5",
          "url": "https://github.com/zkpassport/noir_rsa/commit/3a8b14a322ab6d3772850cce2a98583f5aaf2184"
        },
        "date": 1789376120612,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "exponentiate.json/main",
            "value": 13625,
            "unit": "acir_opcodes"
          },
          {
            "name": "exponentiate_const.json/main",
            "value": 2702,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048.json/main",
            "value": 14131,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048_const.json/main",
            "value": 3208,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pss_2048.json/main",
            "value": 14960,
            "unit": "acir_opcodes"
          },
          {
            "name": "verify_sha256_pss_2048_const.json/main",
            "value": 4037,
            "unit": "acir_opcodes"
          }
        ]
      }
    ],
    "Circuit Size": [
      {
        "commit": {
          "author": {
            "email": "saleel@saleel.xyz",
            "name": "saleel",
            "username": "saleel"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "900e361e8c6bf7761e0a69ee65067b3274790d03",
          "message": "Merge pull request #12 from zkpassport/as/bump-workflows\n\nchore: Bump the workflows",
          "timestamp": "2026-09-11T13:17:13+04:00",
          "tree_id": "8b4f91577c8146eaa67d6e2fc6fc2608f5e1302d",
          "url": "https://github.com/zkpassport/noir_rsa/commit/900e361e8c6bf7761e0a69ee65067b3274790d03"
        },
        "date": 1789118260302,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "test_verify_sha256_pkcs1v15_2048.json/main",
            "value": 16350,
            "unit": "circuit_size"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "75146596+Sarkoxed@users.noreply.github.com",
            "name": "Sarkoxed",
            "username": "Sarkoxed"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5f8bf3a8b52924bf479acf3a6f70ed2d204504e5",
          "message": "Merge pull request #6 from zkpassport/as/noir-rsa-refactoring\n\nchore: Split rsa.nr into modules (no behavior change)",
          "timestamp": "2026-09-14T11:34:35+03:00",
          "tree_id": "5d6142d20c197b5d4390b5024c7d44c5de0fcc82",
          "url": "https://github.com/zkpassport/noir_rsa/commit/5f8bf3a8b52924bf479acf3a6f70ed2d204504e5"
        },
        "date": 1789374941145,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "exponentiate.json/main",
            "value": 66610,
            "unit": "circuit_size"
          },
          {
            "name": "exponentiate_const.json/main",
            "value": 20416,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048.json/main",
            "value": 67164,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048_const.json/main",
            "value": 20971,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pss_2048.json/main",
            "value": 105324,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pss_2048_const.json/main",
            "value": 59142,
            "unit": "circuit_size"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "75146596+Sarkoxed@users.noreply.github.com",
            "name": "Sarkoxed",
            "username": "Sarkoxed"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9adeac2ad1779f0958c1880a443bb33e71fc826a",
          "message": "Merge pull request #14 from zkpassport/as/exponentiation-optimization\n\nchore: optimize exponentiate_signature and add tests (mirror)",
          "timestamp": "2026-09-14T11:52:49+03:00",
          "tree_id": "8cd329372dd5a82e4582f2e64dcd32d410345d77",
          "url": "https://github.com/zkpassport/noir_rsa/commit/9adeac2ad1779f0958c1880a443bb33e71fc826a"
        },
        "date": 1789375997218,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "exponentiate.json/main",
            "value": 51194,
            "unit": "circuit_size"
          },
          {
            "name": "exponentiate_const.json/main",
            "value": 19526,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048.json/main",
            "value": 51749,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048_const.json/main",
            "value": 20081,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pss_2048.json/main",
            "value": 89915,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pss_2048_const.json/main",
            "value": 58252,
            "unit": "circuit_size"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "75146596+Sarkoxed@users.noreply.github.com",
            "name": "Sarkoxed",
            "username": "Sarkoxed"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3a8b14a322ab6d3772850cce2a98583f5aaf2184",
          "message": "Merge pull request #15 from zkpassport/as/mgf1-refactoring\n\nchore: generalize mgf1 over the hash function",
          "timestamp": "2026-09-14T11:54:48+03:00",
          "tree_id": "7e71262ccf7da349d570083d3d3316a4918407a5",
          "url": "https://github.com/zkpassport/noir_rsa/commit/3a8b14a322ab6d3772850cce2a98583f5aaf2184"
        },
        "date": 1789376123893,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "exponentiate.json/main",
            "value": 51194,
            "unit": "circuit_size"
          },
          {
            "name": "exponentiate_const.json/main",
            "value": 19526,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048.json/main",
            "value": 51749,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048_const.json/main",
            "value": 20081,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pss_2048.json/main",
            "value": 89915,
            "unit": "circuit_size"
          },
          {
            "name": "verify_sha256_pss_2048_const.json/main",
            "value": 58252,
            "unit": "circuit_size"
          }
        ]
      }
    ],
    "Brillig Bytecode Size": [
      {
        "commit": {
          "author": {
            "email": "saleel@saleel.xyz",
            "name": "saleel",
            "username": "saleel"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "900e361e8c6bf7761e0a69ee65067b3274790d03",
          "message": "Merge pull request #12 from zkpassport/as/bump-workflows\n\nchore: Bump the workflows",
          "timestamp": "2026-09-11T13:17:13+04:00",
          "tree_id": "8b4f91577c8146eaa67d6e2fc6fc2608f5e1302d",
          "url": "https://github.com/zkpassport/noir_rsa/commit/900e361e8c6bf7761e0a69ee65067b3274790d03"
        },
        "date": 1789118264221,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "test_verify_sha256_pkcs1v15_2048",
            "value": 2451,
            "unit": "opcodes"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "75146596+Sarkoxed@users.noreply.github.com",
            "name": "Sarkoxed",
            "username": "Sarkoxed"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5f8bf3a8b52924bf479acf3a6f70ed2d204504e5",
          "message": "Merge pull request #6 from zkpassport/as/noir-rsa-refactoring\n\nchore: Split rsa.nr into modules (no behavior change)",
          "timestamp": "2026-09-14T11:34:35+03:00",
          "tree_id": "5d6142d20c197b5d4390b5024c7d44c5de0fcc82",
          "url": "https://github.com/zkpassport/noir_rsa/commit/5f8bf3a8b52924bf479acf3a6f70ed2d204504e5"
        },
        "date": 1789374946339,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "exponentiate",
            "value": 2115,
            "unit": "opcodes"
          },
          {
            "name": "exponentiate_const",
            "value": 2104,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048",
            "value": 2432,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048_const",
            "value": 2421,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pss_2048",
            "value": 5408,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pss_2048_const",
            "value": 5397,
            "unit": "opcodes"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "75146596+Sarkoxed@users.noreply.github.com",
            "name": "Sarkoxed",
            "username": "Sarkoxed"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9adeac2ad1779f0958c1880a443bb33e71fc826a",
          "message": "Merge pull request #14 from zkpassport/as/exponentiation-optimization\n\nchore: optimize exponentiate_signature and add tests (mirror)",
          "timestamp": "2026-09-14T11:52:49+03:00",
          "tree_id": "8cd329372dd5a82e4582f2e64dcd32d410345d77",
          "url": "https://github.com/zkpassport/noir_rsa/commit/9adeac2ad1779f0958c1880a443bb33e71fc826a"
        },
        "date": 1789376000432,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "exponentiate",
            "value": 2140,
            "unit": "opcodes"
          },
          {
            "name": "exponentiate_const",
            "value": 2137,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048",
            "value": 2457,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048_const",
            "value": 2454,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pss_2048",
            "value": 5433,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pss_2048_const",
            "value": 5430,
            "unit": "opcodes"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "75146596+Sarkoxed@users.noreply.github.com",
            "name": "Sarkoxed",
            "username": "Sarkoxed"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3a8b14a322ab6d3772850cce2a98583f5aaf2184",
          "message": "Merge pull request #15 from zkpassport/as/mgf1-refactoring\n\nchore: generalize mgf1 over the hash function",
          "timestamp": "2026-09-14T11:54:48+03:00",
          "tree_id": "7e71262ccf7da349d570083d3d3316a4918407a5",
          "url": "https://github.com/zkpassport/noir_rsa/commit/3a8b14a322ab6d3772850cce2a98583f5aaf2184"
        },
        "date": 1789376127709,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "exponentiate",
            "value": 2140,
            "unit": "opcodes"
          },
          {
            "name": "exponentiate_const",
            "value": 2137,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048",
            "value": 2457,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pkcs1v15_2048_const",
            "value": 2454,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pss_2048",
            "value": 3436,
            "unit": "opcodes"
          },
          {
            "name": "verify_sha256_pss_2048_const",
            "value": 3433,
            "unit": "opcodes"
          }
        ]
      }
    ]
  }
}