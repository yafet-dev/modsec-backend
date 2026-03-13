-- CreateTable
CREATE TABLE "GeoAccessControl" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "mode" TEXT NOT NULL DEFAULT 'allow-all',
    "allowedCountries" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "deniedCountries" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GeoAccessControl_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "GeoAccessControl_organizationId_idx" ON "GeoAccessControl"("organizationId");

-- CreateIndex
CREATE INDEX "GeoAccessControl_domain_idx" ON "GeoAccessControl"("domain");

-- CreateIndex
CREATE UNIQUE INDEX "GeoAccessControl_organizationId_domain_key" ON "GeoAccessControl"("organizationId", "domain");

-- AddForeignKey
ALTER TABLE "GeoAccessControl" ADD CONSTRAINT "GeoAccessControl_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
