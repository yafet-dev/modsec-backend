-- Store the normalized source host separately so tenant-scoped queue metrics
-- never need to load and parse the full JSON backlog in the API process.
ALTER TABLE "modsec_landing"
ADD COLUMN "source_host" TEXT;

-- Normalize only the hostname itself. Domain levels are deliberately not
-- broadened: api.example.com and example.com remain different tenants/hosts.
CREATE OR REPLACE FUNCTION public.normalize_modsec_source_host(raw_host TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
  normalized TEXT;
  port_text TEXT;
  closing_bracket INTEGER;
  colon_count INTEGER;
BEGIN
  normalized := btrim(raw_host);
  IF normalized IS NULL OR normalized = '' THEN
    RETURN NULL;
  END IF;

  IF left(normalized, 1) = '[' THEN
    closing_bracket := strpos(normalized, ']');
    IF closing_bracket = 0 THEN
      RETURN NULL;
    END IF;

    IF length(normalized) > closing_bracket THEN
      IF substring(normalized FROM closing_bracket + 1 FOR 1) <> ':' THEN
        RETURN NULL;
      END IF;
      port_text := substring(normalized FROM closing_bracket + 2);
      IF port_text !~ '^[0-9]+$' OR port_text::NUMERIC > 65535 THEN
        RETURN NULL;
      END IF;
    END IF;

    normalized := substring(normalized FROM 2 FOR closing_bracket - 2);
  ELSE
    colon_count := length(normalized) - length(replace(normalized, ':', ''));
    IF colon_count = 1 THEN
      port_text := substring(normalized FROM strpos(normalized, ':') + 1);
      IF port_text !~ '^[0-9]+$' OR port_text::NUMERIC > 65535 THEN
        RETURN NULL;
      END IF;
      normalized := substring(normalized FROM 1 FOR strpos(normalized, ':') - 1);
    END IF;
    -- Multiple colons represent an unbracketed IPv6 literal without a port.
  END IF;

  normalized := regexp_replace(lower(btrim(normalized)), '\.+$', '');
  IF normalized = '' OR normalized ~ '[[:space:]/\\?#@]' THEN
    RETURN NULL;
  END IF;

  RETURN normalized;
EXCEPTION WHEN OTHERS THEN
  -- An attacker-controlled Host header must never be able to abort ingestion.
  RETURN NULL;
END;
$$;

-- JSONB itself is valid, but Fluent Bit may place another JSON document inside
-- a string field. Failed inner casts return NULL instead of failing a write.
CREATE OR REPLACE FUNCTION public.try_parse_modsec_jsonb(raw_json TEXT)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
BEGIN
  RETURN raw_json::JSONB;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$;

-- Resolve the transaction with the processor's deterministic legacy
-- precedence. Once a string wrapper is selected, malformed content returns
-- NULL instead of silently changing the event identity by trying another
-- payload in the same row.
CREATE OR REPLACE FUNCTION public.unwrap_modsec_landing_transaction(
  payload JSONB,
  nesting_depth INTEGER DEFAULT 0
)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
  candidate JSONB;
BEGIN
  IF nesting_depth > 4 OR payload IS NULL THEN
    RETURN NULL;
  END IF;

  IF jsonb_typeof(payload) = 'string' THEN
    candidate := public.try_parse_modsec_jsonb(payload #>> '{}');
    IF candidate IS NULL THEN
      RETURN NULL;
    END IF;
    RETURN public.unwrap_modsec_landing_transaction(
      candidate,
      nesting_depth + 1
    );
  END IF;

  IF jsonb_typeof(payload) <> 'object' THEN
    RETURN NULL;
  END IF;

  IF jsonb_typeof(payload->'raw') = 'string' THEN
    RETURN public.unwrap_modsec_landing_transaction(
      payload->'raw',
      nesting_depth + 1
    );
  ELSIF jsonb_typeof(payload->'data') = 'string' THEN
    RETURN public.unwrap_modsec_landing_transaction(
      payload->'data',
      nesting_depth + 1
    );
  ELSIF jsonb_typeof(payload->'transaction') = 'object' THEN
    RETURN payload->'transaction';
  ELSIF jsonb_typeof(payload->'data') = 'object' THEN
    RETURN public.unwrap_modsec_landing_transaction(
      payload->'data',
      nesting_depth + 1
    );
  END IF;

  -- The remaining supported shape is the transaction object itself.
  IF jsonb_typeof(payload->'request') = 'object' THEN
    RETURN payload;
  END IF;

  RETURN NULL;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION public.extract_modsec_source_host(payload JSONB)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
  transaction_data JSONB;
  request_data JSONB;
  headers_data JSONB;
  raw_host TEXT;
  normalized TEXT;
BEGIN
  transaction_data := public.unwrap_modsec_landing_transaction(payload);
  IF transaction_data IS NULL THEN
    RETURN NULL;
  END IF;

  request_data := transaction_data->'request';
  IF request_data IS NULL OR jsonb_typeof(request_data) <> 'object' THEN
    RETURN NULL;
  END IF;

  IF jsonb_typeof(request_data->'hostname') = 'string' THEN
    raw_host := request_data->>'hostname';
  ELSE
    raw_host := NULL;
  END IF;
  normalized := public.normalize_modsec_source_host(raw_host);
  IF normalized IS NOT NULL AND normalized <> 'unknown' THEN
    RETURN normalized;
  END IF;

  headers_data := request_data->'headers';
  IF headers_data IS NULL OR jsonb_typeof(headers_data) <> 'object' THEN
    RETURN NULL;
  END IF;

  SELECT entry.value #>> '{}'
  INTO raw_host
  FROM jsonb_each(headers_data) AS entry(key, value)
  WHERE lower(entry.key) = 'host'
    AND jsonb_typeof(entry.value) = 'string'
  ORDER BY entry.key
  LIMIT 1;

  RETURN NULLIF(public.normalize_modsec_source_host(raw_host), 'unknown');
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION public.set_modsec_landing_source_host()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW."source_host" := public.extract_modsec_source_host(NEW."data");
  RETURN NEW;
EXCEPTION WHEN OTHERS THEN
  NEW."source_host" := NULL;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "modsec_landing_set_source_host"
BEFORE INSERT OR UPDATE OF "data"
ON "modsec_landing"
FOR EACH ROW
EXECUTE FUNCTION public.set_modsec_landing_source_host();

-- Historical processed rows never participate in this queue metric. Limit the
-- potentially expensive JSON backfill to the exact pending predicate.
UPDATE "modsec_landing"
SET "source_host" = public.extract_modsec_source_host("data")
WHERE "processed" = false;

CREATE INDEX "modsec_landing_pending_source_host_time_idx"
ON "modsec_landing" ("source_host", "time")
WHERE "processed" = false;

-- The processor claims pending rows in ID order with FOR UPDATE SKIP LOCKED.
-- Keep that claim path off the historical processed portion of the table.
CREATE INDEX "modsec_landing_pending_id_idx"
ON "modsec_landing" ("id")
WHERE "processed" = false;
