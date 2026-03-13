-- AlterTable
ALTER TABLE "NotificationSettings" ADD COLUMN     "telegramConnectedAt" TIMESTAMP(3),
ADD COLUMN     "telegramEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "telegramUserId" TEXT;

-- CreateTable
CREATE TABLE "TelegramConnectRequest" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "connectCode" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TelegramConnectRequest_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "TelegramConnectRequest_connectCode_key" ON "TelegramConnectRequest"("connectCode");

-- CreateIndex
CREATE INDEX "TelegramConnectRequest_connectCode_idx" ON "TelegramConnectRequest"("connectCode");

-- CreateIndex
CREATE INDEX "TelegramConnectRequest_userId_idx" ON "TelegramConnectRequest"("userId");
