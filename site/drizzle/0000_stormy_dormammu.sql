CREATE TABLE "account" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"provider_id" text NOT NULL,
	"user_id" text NOT NULL,
	"access_token" text,
	"refresh_token" text,
	"id_token" text,
	"access_token_expires_at" timestamp,
	"refresh_token_expires_at" timestamp,
	"scope" text,
	"password" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "erc8128_invalidation" (
	"id" text PRIMARY KEY NOT NULL,
	"kind" text NOT NULL,
	"match_key" text NOT NULL,
	"address" text NOT NULL,
	"chain_id" integer NOT NULL,
	"signature_hash" text,
	"not_before" integer,
	"expires_at" timestamp,
	CONSTRAINT "erc8128_invalidation_match_key_unique" UNIQUE("match_key")
);
--> statement-breakpoint
CREATE TABLE "erc8128_nonce" (
	"id" text PRIMARY KEY NOT NULL,
	"nonce_key" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	CONSTRAINT "erc8128_nonce_nonce_key_unique" UNIQUE("nonce_key")
);
--> statement-breakpoint
CREATE TABLE "erc8128_verification_cache" (
	"id" text PRIMARY KEY NOT NULL,
	"cache_key" text NOT NULL,
	"address" text NOT NULL,
	"chain_id" integer NOT NULL,
	"signature_hash" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	CONSTRAINT "erc8128_verification_cache_cache_key_unique" UNIQUE("cache_key")
);
--> statement-breakpoint
CREATE TABLE "session" (
	"id" text PRIMARY KEY NOT NULL,
	"expires_at" timestamp NOT NULL,
	"token" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"user_id" text NOT NULL,
	CONSTRAINT "session_token_unique" UNIQUE("token")
);
--> statement-breakpoint
CREATE TABLE "user" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"email" text NOT NULL,
	"email_verified" boolean DEFAULT false NOT NULL,
	"image" text,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "user_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "verification" (
	"id" text PRIMARY KEY NOT NULL,
	"identifier" text NOT NULL,
	"value" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wallet_address" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"address" text NOT NULL,
	"chain_id" integer NOT NULL,
	"is_primary" boolean DEFAULT false,
	"created_at" timestamp NOT NULL
);
--> statement-breakpoint
ALTER TABLE "account" ADD CONSTRAINT "account_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wallet_address" ADD CONSTRAINT "wallet_address_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "account_userId_idx" ON "account" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "erc8128Invalidation_kind_idx" ON "erc8128_invalidation" USING btree ("kind");--> statement-breakpoint
CREATE INDEX "erc8128Invalidation_address_idx" ON "erc8128_invalidation" USING btree ("address");--> statement-breakpoint
CREATE INDEX "erc8128Invalidation_chainId_idx" ON "erc8128_invalidation" USING btree ("chain_id");--> statement-breakpoint
CREATE INDEX "erc8128Invalidation_signatureHash_idx" ON "erc8128_invalidation" USING btree ("signature_hash");--> statement-breakpoint
CREATE INDEX "erc8128Invalidation_expiresAt_idx" ON "erc8128_invalidation" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "erc8128Nonce_expiresAt_idx" ON "erc8128_nonce" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "erc8128VerificationCache_address_idx" ON "erc8128_verification_cache" USING btree ("address");--> statement-breakpoint
CREATE INDEX "erc8128VerificationCache_chainId_idx" ON "erc8128_verification_cache" USING btree ("chain_id");--> statement-breakpoint
CREATE INDEX "erc8128VerificationCache_signatureHash_idx" ON "erc8128_verification_cache" USING btree ("signature_hash");--> statement-breakpoint
CREATE INDEX "erc8128VerificationCache_expiresAt_idx" ON "erc8128_verification_cache" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "session_userId_idx" ON "session" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "verification_identifier_idx" ON "verification" USING btree ("identifier");--> statement-breakpoint
CREATE INDEX "walletAddress_userId_idx" ON "wallet_address" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "walletAddress_address_idx" ON "wallet_address" USING btree ("address");