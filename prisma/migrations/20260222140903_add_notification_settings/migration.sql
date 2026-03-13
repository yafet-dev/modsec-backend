-- CreateTable
CREATE TABLE "NotificationSettings" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "notificationType" TEXT NOT NULL,
    "emailList" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "telegramChatId" TEXT,
    "domainFilter" TEXT NOT NULL DEFAULT 'all',
    "selectedDomains" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "severityFilter" TEXT NOT NULL DEFAULT 'all',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationSettings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "NotificationSettings_organizationId_idx" ON "NotificationSettings"("organizationId");

-- CreateIndex
CREATE INDEX "NotificationSettings_notificationType_idx" ON "NotificationSettings"("notificationType");

-- CreateIndex
CREATE INDEX "NotificationSettings_enabled_idx" ON "NotificationSettings"("enabled");

-- AddForeignKey
ALTER TABLE "NotificationSettings" ADD CONSTRAINT "NotificationSettings_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
