#!/usr/bin/env python3
"""
Generate mock data for the specified schema.
"""
import json
import random
import sqlite3
import time
import uuid

DB_FILE = "rustion.db"


# ------------------------------------------------------------------
# 2.  Helpers
# ------------------------------------------------------------------
def uuid4():
    return str(uuid.uuid4())


def now_ts():
    return int(time.time())


def rand_future_ts(from_ts=None, days=365):
    if from_ts is None:
        from_ts = now_ts()
    return from_ts + random.randint(60, days * 24 * 3600)


def rand_past_ts(from_ts=None, days=365):
    if from_ts is None:
        from_ts = now_ts()
    return from_ts - random.randint(60, days * 24 * 3600)


# ------------------------------------------------------------------
# 3.  Generate
# ------------------------------------------------------------------
def generate():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    # cur.executescript(SCHEMA_SQL)
    admin_id = cur.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()[
        0
    ]

    # 3.1  Users ----------------------------------------------------
    users = []
    for i in range(1, 6):
        user = {
            "id": uuid4(),
            "username": f"user{i}",
            "email": f"user{i}@example.com",
            "password_hash": f"hash{i}",
            "authorized_keys": json.dumps([f"ssh-rsa key{i}"]),
            "force_init_pass": random.choice([0, 1]),
            "is_active": 1,
            "updated_by": admin_id,
            "updated_at": now_ts() * 1000 + random.randint(0, 1000),
        }
        users.append(user)
    cur.executemany(
        """
        INSERT INTO users
        (id, username, email, password_hash, authorized_keys,
         force_init_pass, is_active, updated_by, updated_at)
        VALUES
        (:id, :username, :email, :password_hash, :authorized_keys,
         :force_init_pass, :is_active, :updated_by, :updated_at)
        """,
        users,
    )

    # 3.2  Targets --------------------------------------------------
    targets = []
    for i in range(1, 201):
        target = {
            "id": uuid4(),
            "name": f"target-{i}",
            "hostname": f"host-{i}.example.com",
            "port": random.randint(1024, 65535),
            "server_public_key": f"pubkey-{i}",
            "description": f"Target number {i}",
            "is_active": random.choice([0, 1, 1, 1]),
            "updated_by": random.choice(users)["id"],
            "updated_at": now_ts() * 1000 + random.randint(0, 1000),
        }
        targets.append(target)
    cur.executemany(
        """
        INSERT INTO targets
        (id, name, hostname, port, server_public_key, description,
         is_active, updated_by, updated_at)
        VALUES
        (:id, :name, :hostname, :port, :server_public_key, :description,
         :is_active, :updated_by, :updated_at)
        """,
        targets,
    )

    # 3.3  Secrets --------------------------------------------------
    secrets = []
    for i in range(1, 21):
        secret = {
            "id": uuid4(),
            "name": f"secret-{i}",
            "user": random.choice(["root", "alice", "bob"]),
            "password": f"pw{i}",
            "private_key": None,
            "public_key": None,
            "is_active": random.choice([0, 1, 1, 1]),
            "updated_by": random.choice(users)["id"],
            "updated_at": now_ts() * 1000 + random.randint(0, 1000),
        }
        secrets.append(secret)
    cur.executemany(
        """
        INSERT INTO secrets
        (id, name, user, password, private_key, public_key,
         is_active, updated_by, updated_at)
        VALUES
        (:id, :name, :user, :password, :private_key, :public_key,
         :is_active, :updated_by, :updated_at)
        """,
        secrets,
    )

    # 3.4  Target-Secrets (each target gets 3 random secrets) -------
    target_secrets = []
    for t in targets:
        chosen = random.sample(secrets, 3)
        for s in chosen:
            ts = {
                "id": uuid4(),
                "target_id": t["id"],
                "secret_id": s["id"],
                "is_active": random.choice([0, 1, 1, 1]),
                "updated_by": random.choice(users)["id"],
                "updated_at": now_ts() * 1000 + random.randint(0, 1000),
            }
            target_secrets.append(ts)
    cur.executemany(
        """
        INSERT INTO target_secrets
        (id, target_id, secret_id, is_active, updated_by, updated_at)
        VALUES
        (:id, :target_id, :secret_id, :is_active, :updated_by, :updated_at)
        """,
        target_secrets,
    )

    casbin_rule = []
    for g in ["apple", "banana", "peach"]:
        ts_chosen = random.sample(target_secrets, 100)
        for t in ts_chosen:
            cr = {
                "id": uuid4(),
                "ptype": "g2",
                "v0": t["id"],
                "v1": g,
                "v2": "",
                "v3": "",
                "v4": "",
                "v5": "",
                "updated_by": random.choice(users)["id"],
                "updated_at": now_ts() * 1000 + random.randint(0, 1000),
            }
            casbin_rule.append(cr)

    for u in users:
        cr = {
            "id": uuid4(),
            "ptype": "g1",
            "v0": u["id"],
            "v1": "login_group",
            "v2": "",
            "v3": "",
            "v4": "",
            "v5": "",
            "updated_by": random.choice(users)["id"],
            "updated_at": now_ts() * 1000 + random.randint(0, 1000),
        }
        casbin_rule.append(cr)

    for u in users:
        cr = {
            "id": uuid4(),
            "ptype": "p",
            "v0": u["id"],
            "v1": random.choice(["apple", "banana", "peach"]),
            "v2": random.choice(["exec", "shell"]),
            "v3": "",
            "v4": "",
            "v5": "",
            "updated_by": random.choice(users)["id"],
            "updated_at": now_ts() * 1000 + random.randint(0, 1000),
        }
        casbin_rule.append(cr)

    cur.executemany(
        """
        INSERT INTO casbin_rule
        (id, ptype, v0, v1, v2, v3, v4, v5, updated_by, updated_at)
        VALUES
        (:id, :ptype, :v0, :v1, :v2, :v3, :v4, :v5, :updated_by, :updated_at)
        """,
        casbin_rule,
    )

    conn.commit()
    conn.close()
    print("✅  Mock data generated successfully.")


if __name__ == "__main__":
    generate()
