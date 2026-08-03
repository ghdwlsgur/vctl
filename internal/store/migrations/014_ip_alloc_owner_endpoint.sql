-- A VIP's owning WireGuard endpoint, stated rather than guessed.
--
-- The dashboard decided which endpoint a DNAT VIP belongs to by taking the first
-- token of the endpoint's display label and asking whether the VIP's label
-- contained it, longest match winning. That is substring matching on two
-- human-typed strings: it attaches a VIP to the wrong endpoint whenever one
-- label happens to contain another's prefix, it attaches nothing when somebody
-- renames either side, and the graph never says which of those happened.
--
-- The public key is the endpoint's identity everywhere else in this schema, so
-- it is what a VIP points at here too. Nullable on purpose — most rows will not
-- have it filled in for a while, and the renderer keeps the old guess for those,
-- clearly marked as a guess.
ALTER TABLE ip_allocations
    ADD COLUMN IF NOT EXISTS owner_public_key TEXT NOT NULL DEFAULT '';

-- Only the VIPs that name an owner are looked up, and there are few of them.
CREATE INDEX IF NOT EXISTS idx_ip_allocations_owner_key
    ON ip_allocations (owner_public_key) WHERE owner_public_key <> '';
