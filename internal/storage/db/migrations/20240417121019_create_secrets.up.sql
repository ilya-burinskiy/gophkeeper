CREATE TABLE "secrets" (
    "id" bigserial PRIMARY KEY,
    "user_id" bigint references "users"("id") NOT NULL,
    "type" integer NOT NULL,
    "description" varchar(500) NOT NULL DEFAULT '',
    "encrypted_data" bytea NOT NULL,
    "encrypted_key" bytea NOT NULL
);
