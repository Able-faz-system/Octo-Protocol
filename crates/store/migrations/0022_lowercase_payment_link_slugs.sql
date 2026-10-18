-- Payment-link slugs become case-insensitive: `/pay/AcmePay` and `/pay/acmepay` must be the same
-- page, never two visually identical pages owned by different merchants.
--
-- Collision resolution for pre-existing rows that differ only by case: the OLDEST row (by
-- created_at, then id) keeps the lowercased slug; every newer row in the group is renamed to
-- `<lowercased slug>-<its own id as 32 hex chars>`, which is unique because ids are. The renamed
-- links' old URLs stop resolving to them — they would have been ambiguous anyway.
WITH ranked AS (
    SELECT id, row_number() OVER (PARTITION BY lower(slug) ORDER BY created_at, id) AS rn
    FROM payment_links
)
UPDATE payment_links p
SET slug = lower(p.slug) || '-' || replace(p.id::text, '-', ''), updated_at = now()
FROM ranked r
WHERE p.id = r.id AND r.rn > 1;

-- Every remaining case-group now has exactly one row, so lowercasing can't collide.
UPDATE payment_links SET slug = lower(slug), updated_at = now() WHERE slug <> lower(slug);

-- Store only lowercase slugs, and enforce uniqueness on the lowercased value (also serves the
-- `lower(slug) = lower($1)` lookup in get_payment_link_by_slug).
ALTER TABLE payment_links ADD CONSTRAINT payment_links_slug_lowercase CHECK (slug = lower(slug));
ALTER TABLE payment_links DROP CONSTRAINT IF EXISTS payment_links_slug_key;
CREATE UNIQUE INDEX payment_links_slug_lower_unique_idx ON payment_links (lower(slug));
