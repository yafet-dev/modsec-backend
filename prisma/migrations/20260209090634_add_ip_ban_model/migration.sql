-- CreateTable
CREATE TABLE "IPBan" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "domains" TEXT[],
    "country" TEXT,
    "countryName" TEXT,
    "reason" TEXT,
    "bannedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IPBan_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "IPBan_organizationId_idx" ON "IPBan"("organizationId");

-- CreateIndex
CREATE INDEX "IPBan_ip_idx" ON "IPBan"("ip");

-- CreateIndex
CREATE INDEX "IPBan_bannedAt_idx" ON "IPBan"("bannedAt");

-- CreateIndex
CREATE UNIQUE INDEX "IPBan_organizationId_ip_key" ON "IPBan"("organizationId", "ip");

-- AddForeignKey
ALTER TABLE "IPBan" ADD CONSTRAINT "IPBan_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
