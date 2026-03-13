-- CreateTable
CREATE TABLE "IPBanToken" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "domains" TEXT[],
    "token" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IPBanToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "IPBanToken_token_key" ON "IPBanToken"("token");

-- CreateIndex
CREATE INDEX "IPBanToken_token_idx" ON "IPBanToken"("token");

-- CreateIndex
CREATE INDEX "IPBanToken_organizationId_idx" ON "IPBanToken"("organizationId");

-- CreateIndex
CREATE INDEX "IPBanToken_expiresAt_idx" ON "IPBanToken"("expiresAt");
