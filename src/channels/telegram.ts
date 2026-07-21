import https from 'https';

import { Api, Bot } from 'grammy';

import { ASSISTANT_NAME } from '../config.js';
import { readEnvFile } from '../env.js';
import { log } from '../log.js';
import type { ChannelAdapter, ChannelDefaults, ChannelSetup, OutboundMessage } from './adapter.js';
import { registerChannelAdapter } from './channel-registry.js';

const TELEGRAM_DEFAULTS: ChannelDefaults = {
  dm: { engageMode: 'pattern', engagePattern: '.', threads: false, unknownSenderPolicy: 'request_approval' },
  group: { engageMode: 'mention-sticky', threads: false, unknownSenderPolicy: 'request_approval' },
  mentions: 'platform',
};

async function sendTelegramMessage(
  api: { sendMessage: Api['sendMessage'] },
  chatId: string | number,
  text: string,
  options: { message_thread_id?: number } = {},
): Promise<void> {
  try {
    await api.sendMessage(chatId, text, { ...options, parse_mode: 'Markdown' });
  } catch {
    await api.sendMessage(chatId, text, options);
  }
}

function createAdapter(): ChannelAdapter | null {
  const envVars = readEnvFile(['TELEGRAM_BOT_TOKEN']);
  const token = process.env.TELEGRAM_BOT_TOKEN || envVars.TELEGRAM_BOT_TOKEN || '';
  if (!token) {
    log.warn('Telegram: TELEGRAM_BOT_TOKEN not set');
    return null;
  }

  let bot: Bot | null = null;

  return {
    name: 'telegram',
    channelType: 'telegram',
    supportsThreads: false,
    defaults: TELEGRAM_DEFAULTS,

    async setup(config: ChannelSetup): Promise<void> {
      bot = new Bot(token, {
        client: { baseFetchConfig: { agent: https.globalAgent, compress: true } },
      });

      bot.command('chatid', (ctx) => {
        const chatId = ctx.chat.id;
        const chatName =
          ctx.chat.type === 'private'
            ? ctx.from?.first_name || 'Private'
            : (ctx.chat as { title?: string }).title || 'Unknown';
        ctx.reply(`Chat ID: \`tg:${chatId}\`\nName: ${chatName}\nType: ${ctx.chat.type}`, {
          parse_mode: 'Markdown',
        });
      });

      bot.command('ping', (ctx) => {
        ctx.reply(`${ASSISTANT_NAME} is online.`);
      });

      const TELEGRAM_BOT_COMMANDS = new Set(['chatid', 'ping']);

      bot.on('message:text', async (ctx) => {
        if (ctx.message.text.startsWith('/')) {
          const cmd = ctx.message.text.slice(1).split(/[\s@]/)[0].toLowerCase();
          if (TELEGRAM_BOT_COMMANDS.has(cmd)) return;
        }

        const chatJid = `tg:${ctx.chat.id}`;
        const text = ctx.message.text;
        const timestamp = new Date(ctx.message.date * 1000).toISOString();
        const senderName = ctx.from?.first_name || ctx.from?.username || ctx.from?.id.toString() || 'Unknown';
        const senderId = ctx.from?.id.toString() || '';
        const threadId = ctx.message.message_thread_id?.toString() ?? null;
        const isGroup = ctx.chat.type === 'group' || ctx.chat.type === 'supergroup';
        const chatName = ctx.chat.type === 'private' ? senderName : (ctx.chat as { title?: string }).title || chatJid;

        let isMention = false;
        const botUsername = ctx.me?.username?.toLowerCase();
        if (botUsername) {
          const entities = ctx.message.entities || [];
          isMention = entities.some((entity) => {
            if (entity.type === 'mention') {
              const mentionText = text.substring(entity.offset, entity.offset + entity.length).toLowerCase();
              return mentionText === `@${botUsername}`;
            }
            return false;
          });
        }

        config.onMetadata(chatJid, chatName, isGroup);
        config.onInbound(chatJid, threadId, {
          id: ctx.message.message_id.toString(),
          kind: 'chat',
          content: { text, sender: senderName, senderId: `tg:${senderId}` },
          timestamp,
          isMention,
          isGroup,
        });

        log.info('Telegram message stored', { chatJid, chatName, sender: senderName });
      });

      const storeMedia = (
        ctx: {
          chat: { id: number; type: string; title?: string };
          message: { date: number; message_id: number; caption?: string };
          from?: { first_name?: string; username?: string; id?: number };
        },
        placeholder: string,
      ) => {
        const chatJid = `tg:${ctx.chat.id}`;
        const timestamp = new Date(ctx.message.date * 1000).toISOString();
        const senderName = ctx.from?.first_name || ctx.from?.username || ctx.from?.id?.toString() || 'Unknown';
        const caption = ctx.message.caption ? ` ${ctx.message.caption}` : '';
        const isGroup = ctx.chat.type === 'group' || ctx.chat.type === 'supergroup';
        config.onMetadata(chatJid, undefined, isGroup);
        config.onInbound(chatJid, null, {
          id: ctx.message.message_id.toString(),
          kind: 'chat',
          content: { text: `${placeholder}${caption}`, sender: senderName, senderId: `tg:${ctx.from?.id ?? ''}` },
          timestamp,
          isGroup,
        });
      };

      bot.on('message:photo', (ctx) => storeMedia(ctx as Parameters<typeof storeMedia>[0], '[Photo]'));
      bot.on('message:video', (ctx) => storeMedia(ctx as Parameters<typeof storeMedia>[0], '[Video]'));
      bot.on('message:voice', (ctx) => storeMedia(ctx as Parameters<typeof storeMedia>[0], '[Voice message]'));
      bot.on('message:audio', (ctx) => storeMedia(ctx as Parameters<typeof storeMedia>[0], '[Audio]'));
      bot.on('message:document', (ctx) => {
        const name = (ctx.message as { document?: { file_name?: string } }).document?.file_name || 'file';
        storeMedia(ctx as Parameters<typeof storeMedia>[0], `[Document: ${name}]`);
      });
      bot.on('message:sticker', (ctx) => {
        const emoji = (ctx.message as { sticker?: { emoji?: string } }).sticker?.emoji || '';
        storeMedia(ctx as Parameters<typeof storeMedia>[0], `[Sticker ${emoji}]`);
      });
      bot.on('message:location', (ctx) => storeMedia(ctx as Parameters<typeof storeMedia>[0], '[Location]'));
      bot.on('message:contact', (ctx) => storeMedia(ctx as Parameters<typeof storeMedia>[0], '[Contact]'));

      bot.catch((err) => {
        log.error('Telegram bot error', { err: err.message });
      });

      return new Promise<void>((resolve) => {
        bot!.start({
          onStart: (botInfo) => {
            log.info('Telegram bot connected', { username: botInfo.username, id: botInfo.id });
            resolve();
          },
        });
      });
    },

    async teardown(): Promise<void> {
      if (bot) {
        bot.stop();
        bot = null;
        log.info('Telegram bot stopped');
      }
    },

    isConnected(): boolean {
      return bot !== null;
    },

    async deliver(platformId: string, threadId: string | null, message: OutboundMessage): Promise<string | undefined> {
      if (!bot) return undefined;
      const content = message.content as Record<string, unknown> | string | undefined;
      const text = typeof content === 'string' ? content : typeof content?.text === 'string' ? content.text : '';
      if (!text) return undefined;
      const numericId = platformId.replace(/^tg:/, '');
      const options = threadId ? { message_thread_id: parseInt(threadId, 10) } : {};
      const MAX = 4096;
      if (text.length <= MAX) {
        await sendTelegramMessage(bot.api, numericId, text, options);
      } else {
        for (let i = 0; i < text.length; i += MAX) {
          await sendTelegramMessage(bot.api, numericId, text.slice(i, i + MAX), options);
        }
      }
      log.info('Telegram message sent', { platformId, length: text.length });
      return undefined;
    },

    async setTyping(platformId: string, _threadId: string | null): Promise<void> {
      if (!bot) return;
      try {
        const numericId = platformId.replace(/^tg:/, '');
        await bot.api.sendChatAction(numericId, 'typing');
      } catch (err) {
        log.debug('Failed to send Telegram typing indicator', { platformId, err });
      }
    },
  };
}

registerChannelAdapter('telegram', { factory: createAdapter, defaults: TELEGRAM_DEFAULTS });
