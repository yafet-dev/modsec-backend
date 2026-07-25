-- AlterTable
ALTER TABLE "User" ADD COLUMN "authUserId" TEXT;

-- CreateTable
CREATE TABLE "AuthEmailToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "purpose" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "authUserId" TEXT NOT NULL,
    "organizationMemberId" TEXT,
    "requiresPassword" BOOLEAN NOT NULL DEFAULT false,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthEmailToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_authUserId_key" ON "User"("authUserId");

-- CreateIndex
CREATE UNIQUE INDEX "AuthEmailToken_tokenHash_key" ON "AuthEmailToken"("tokenHash");

-- CreateIndex
CREATE INDEX "AuthEmailToken_email_purpose_idx" ON "AuthEmailToken"("email", "purpose");

-- CreateIndex
CREATE INDEX "AuthEmailToken_authUserId_purpose_idx" ON "AuthEmailToken"("authUserId", "purpose");

-- CreateIndex
CREATE INDEX "AuthEmailToken_organizationMemberId_idx" ON "AuthEmailToken"("organizationMemberId");

-- CreateIndex
CREATE INDEX "AuthEmailToken_purpose_consumedAt_expiresAt_idx" ON "AuthEmailToken"("purpose", "consumedAt", "expiresAt");

-- CreateIndex
CREATE INDEX "AuthEmailToken_expiresAt_idx" ON "AuthEmailToken"("expiresAt");
