/**
 * Email Verification, Disposable Domain, MX/SPF/DMARC & Domain Fraud Risk Scoring API
 * Cloudflare Worker running on Cloudflare Global Edge using Cloudflare DoH (DNS over HTTPS)
 * Zero external SaaS costs, sub-50ms latency, RapidAPI proxy-secret secured.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-RapidAPI-Key, X-RapidAPI-Host, X-RapidAPI-Proxy-Secret',
  'Access-Control-Max-Age': '86400',
};

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...CORS_HEADERS,
      ...extraHeaders,
    },
  });
}

const ROLE_ACCOUNTS = new Set([
  'admin', 'administrator', 'support', 'billing', 'info', 'contact', 'sales',
  'help', 'helpdesk', 'security', 'abuse', 'postmaster', 'hostmaster', 'webmaster',
  'compliance', 'legal', 'finance', 'marketing', 'press', 'media', 'team', 'office',
  'hr', 'careers', 'jobs', 'accounting', 'inquiries', 'devnull', 'noreply', 'no-reply',
  'root', 'orders', 'service', 'operations', 'privacy', 'investors', 'editor',
  'feedback', 'general', 'hello', 'hi', 'enquiries'
]);

const FREE_EMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de',
  'yahoo.es', 'yahoo.it', 'yahoo.co.jp', 'hotmail.com', 'hotmail.co.uk', 'hotmail.fr',
  'hotmail.de', 'hotmail.es', 'hotmail.it', 'outlook.com', 'live.com', 'msn.com',
  'icloud.com', 'me.com', 'mac.com', 'protonmail.com', 'proton.me', 'aol.com',
  'zoho.com', 'mail.com', 'gmx.com', 'gmx.de', 'gmx.net', 'yandex.com', 'yandex.ru',
  'mail.ru', 'inbox.lv', 'tutanota.com', 'tuta.io', 'fastmail.com', 'hushmail.com'
]);

const DISPOSABLE_DOMAINS = new Set([
  '0-mail.com', '0815.ru', '0clickemail.com', '10mail.org', '10minutemail.com',
  '10minutemail.de', '10minutemail.net', '10minutemail.org', '20minutemail.com',
  '33mail.com', 'abyssmail.com', 'airmail.cc', 'anonbox.net', 'anonymbox.com',
  'antichef.com', 'binkmail.com', 'bobmail.info', 'bofthew.com', 'boun.cr',
  'bugmenot.com', 'burnermail.io', 'byom.de', 'chacuo.net', 'Clipmail.eu',
  'courrieltemporaire.com', 'crazymailing.com', 'cuvox.de', 'dacoolest.com',
  'dandikmail.com', 'dayrep.com', 'deadaddress.com', 'deadspam.com', 'despam.it',
  'devnullmail.com', 'discard.email', 'discardmail.com', 'discardmail.de',
  'disposable.com', 'disposable.email', 'disposableaddress.com', 'disposableinbox.com',
  'disposemail.com', 'dispostable.com', 'dodgeit.com', 'dodgit.com', 'dontreg.com',
  'dontsendmespam.de', 'drdrb.com', 'dropmail.me', 'dump-email.info', 'dumpmail.de',
  'dumpyemail.com', 'e4ward.com', 'easytrashmail.com', 'einrot.com', 'email-fake.com',
  'email60.com', 'emaildrop.io', 'emailfake.com', 'emailias.com', 'emailinfive.com',
  'emailmiser.com', 'emailna.co', 'emailondeck.com', 'emailproxsy.com',
  'emailsensei.com', 'emailtemporaire.fr', 'emailthe.net', 'emailtmp.com',
  'emailwarden.com', 'emailx.at.tc', 'emkei.cz', 'ephemail.net', 'eyepaste.com',
  'fakeinbox.com', 'fakemail.fr', 'fakemail.net', 'fakemailgenerator.com',
  'fastacura.com', 'filzmail.com', 'fleckens.hu', 'flyspam.com', 'garbagemail.org',
  'getairmail.com', 'getnada.com', 'getonemail.com', 'gishpuppy.com', 'grr.la',
  'guerrillamail.biz', 'guerrillamail.com', 'guerrillamail.de', 'guerrillamail.info',
  'guerrillamail.net', 'guerrillamail.org', 'guerrillamailblock.com', 'gustr.com',
  'harakirimail.com', 'hidemail.de', 'hmamail.com', 'hulapla.de', 'inboxalias.com',
  'inboxbear.com', 'inboxclean.com', 'inboxkitten.com', 'incognitomail.org',
  'instantemailaddress.com', 'ipoo.org', 'jetable.com', 'jetable.fr.nf',
  'jetable.net', 'jetable.org', 'jourrapide.com', 'junk1e.com', 'kasmail.com',
  'killmail.com', 'killmail.net', 'klzlk.com', 'koszmail.pl', 'kurzepost.de',
  'letthemeatspam.com', 'lhsdv.com', 'lifebyfood.com', 'link2mail.net',
  'litedrop.com', 'lol.ovpn.to', 'lookugly.com', 'lopl.co.cc', 'lr78.com',
  'maileater.com', 'mailexpire.com', 'mailCatch.com', 'maildrop.cc', 'mailforspam.com',
  'mailfreeonline.com', 'mailfs.com', 'mailin8r.com', 'mailinater.com',
  'mailinator.com', 'mailinator.net', 'mailinator.org', 'mailinator2.com',
  'mailincubator.com', 'mailismagic.com', 'mailmate.com', 'mailme.ir', 'mailme.lv',
  'mailmetrash.com', 'mailmoat.com', 'mailnesia.com', 'mailnull.com', 'mailorg.org',
  'mailpick.biz', 'mailproxsy.com', 'mailquack.com', 'mailrock.biz', 'mailsac.com',
  'mailscrap.com', 'mailseal.de', 'mailshell.com', 'mailsiphon.com', 'mailslite.com',
  'mailslurp.com', 'mailtemp.info', 'mailtothis.com', 'mailtrash.net', 'mailzi.ru',
  'mailzilla.com', 'makemetheking.com', 'manybrain.com', 'mbx.cc', 'mega.zik.dj',
  'meinspamschutz.de', 'meltmail.com', 'messagebeamer.de', 'mierdamail.com',
  'mintemail.com', 'mjukglass.nu', 'moakt.cc', 'moakt.com', 'moakt.ws',
  'moburl.com', 'moncourrier.fr.nf', 'monemail.fr.nf', 'monmail.fr.nf', 'msa.minsmail.com',
  'mt2009.com', 'mt2014.com', 'mt2015.com', 'my10minutemail.com', 'mycleaninbox.net',
  'mypartyclip.de', 'myphantomemail.com', 'mysamp.de', 'myspaceinc.com',
  'myspaceinc.net', 'myspacepimpedup.com', 'mytemp.email', 'mytempemail.com',
  'mytrashmail.com', 'nada.ltd', 'neomailbox.com', 'nepwk.com', 'nervmich.net',
  'nervtmich.net', 'netmails.com', 'netmails.net', 'netzidiot.de', 'neverbox.com',
  'no-spam.ws', 'nobulk.com', 'noclickemail.com', 'nogmailspam.info', 'nomail.xl.cx',
  'nomail2me.com', 'nomorespamemails.com', 'nospam.ze.tc', 'nospam4.us',
  'nospamfor.us', 'nospammail.net', 'nospamthanks.info', 'notmailinator.com',
  'nowmymail.com', 'nurfuerspam.de', 'nus.edu.sg', 'nwldx.com', 'objectmail.com',
  'obobbo.com', 'oneoffemail.com', 'onewaymail.com', 'online.ms', 'oopi.org',
  'opayq.com', 'ordinaryamerican.net', 'otherinbox.com', 'ourklips.com',
  'outlawspam.com', 'ovpn.to', 'owlpic.com', 'pancakemail.com', 'pimpedupmyspace.com',
  'pjjkp.com', 'plexolan.de', 'poczta.onet.pl', 'politikerclub.de', 'poofy.org',
  'pookmail.com', 'privacy.net', 'proxymail.eu', 'prtnx.com', 'punkass.com',
  'putthisinyourspamdatabase.com', 'qq.com', 'quickinbox.com', 'rcpt.at',
  'reallymymail.com', 'realtyalerts.ca', 'recode.me', 'recursor.net', 'regbypass.com',
  'rmqkr.net', 'rppkn.com', 'rtrtr.com', 's0ny.net', 'safe-mail.net',
  'safersignup.de', 'safetymail.info', 'safetypost.de', 'sandelf.de',
  'saynotospams.com', 'schafmail.de', 'Selfdestructingmail.com', 'sendspamhere.com',
  'sharklasers.com', 'shiftmail.com', 'shitmail.me', 'shortmail.net', 'sibmail.com',
  'skeefmail.com', 'slaskpost.se', 'slopsbox.com', 'smellfear.com', 'snakemail.com',
  'sneakemail.com', 'sofimail.com', 'sofort-mail.de', 'sogetthis.com',
  'soodonims.com', 'spam.la', 'spam.su', 'spam4.me', 'spamavert.com', 'spambob.com',
  'spambob.net', 'spambob.org', 'spambog.com', 'spambog.de', 'spambog.ru',
  'spambox.info', 'spambox.us', 'spamcannon.com', 'spamcannon.net', 'spamcero.com',
  'spamcon.org', 'spamcorptastic.com', 'spamcowboy.com', 'spamcowboy.net',
  'spamcowboy.org', 'spamday.com', 'spameater.com', 'spameater.org', 'spamex.com',
  'spamfree24.com', 'spamfree24.de', 'spamfree24.eu', 'spamfree24.info',
  'spamfree24.net', 'spamfree24.org', 'spamgoes.in', 'spamgourmet.com',
  'spamgourmet.net', 'spamgourmet.org', 'spamherelots.com', 'spamhereplease.com',
  'spamhole.com', 'spamify.com', 'spaminator.de', 'spamkill.info', 'spaml.com',
  'spaml.de', 'spammotel.com', 'spamobox.com', 'spamoff.de', 'spamslicer.com',
  'spamspot.com', 'spamthis.co.uk', 'spamthisplease.com', 'spamtrail.com',
  'spamtroll.net', 'speed.1s.fr', 'supergreatmail.com', 'supermailer.jp',
  'superrito.com', 'suremail.info', 'teewars.org', 'teleworm.com', 'teleworm.us',
  'temp-mail.de', 'temp-mail.io', 'temp-mail.org', 'temp-mail.ru', 'tempail.com',
  'tempalias.com', 'tempe-mail.com', 'tempemail.biz', 'tempemail.co.za',
  'tempemail.com', 'tempemail.net', 'tempinbox.co.uk', 'tempinbox.com',
  'tempmail.co', 'tempmail.com', 'tempmail.de', 'tempmail.eu', 'tempmail.it',
  'tempmail.net', 'tempmail.org', 'tempmail.us', 'tempmail2.com', 'tempmaildemo.com',
  'tempmailer.com', 'tempmailer.de', 'tempomail.fr', 'temporarily.de',
  'temporarioemail.com.br', 'temporaryemail.net', 'temporaryforwarding.com',
  'temporaryinbox.com', 'temporarymailaddress.com', 'thanksnospam.info',
  'thankyou2010.com', 'thisisnotmyrealemail.com', 'throwawayemailaddress.com',
  'throwawaymail.com', 'tilien.com', 'tmailinator.com', 'tradermail.info',
  'trash-amil.com', 'trash-mail.at', 'trash-mail.com', 'trash-mail.de',
  'trash2009.com', 'trashemail.de', 'trashmail.at', 'trashmail.com', 'trashmail.de',
  'trashmail.me', 'trashmail.net', 'trashmail.org', 'trashmail.ws', 'trashmailer.com',
  'trashymail.com', 'trashymail.net', 'trbvm.com', 'turual.com', 'twinmail.de',
  'tyldd.com', 'uggsrock.com', 'upliftnow.com', 'uplipht.com', 'venompen.com',
  'veryrealemail.com', 'viditag.com', 'viewcastmedia.com', 'wegwerfadresse.de',
  'wegwerfemail.com', 'wegwerfemail.de', 'wegwerfmail.de', 'wegwerfmail.info',
  'wegwerfmail.net', 'wegwerfmail.org', 'wh4f.org', 'whyspam.me', 'willselfdestruct.com',
  'winemaven.info', 'wronghead.com', 'wuzup.net', 'wuzupmail.net', 'xagloo.com',
  'xemaps.com', 'xents.com', 'xmaily.com', 'xoxy.net', 'yep.it', 'yogamaven.com',
  'yopmail.com', 'yopmail.fr', 'yopmail.net', 'ypmail.webarnak.fr.eu.org',
  'yuurok.com', 'zehnminutenmail.de', 'zippymail.info', 'zoaxe.com', 'zoemail.org'
]);

function validateRfc5322Syntax(email) {
  if (typeof email !== 'string') {
    return { valid: false, error: 'Email must be a string' };
  }
  const trimmed = email.trim().toLowerCase();
  if (!trimmed || trimmed.length > 254) {
    return { valid: false, error: 'Email length must be between 1 and 254 characters' };
  }
  const atIndex = trimmed.lastIndexOf('@');
  if (atIndex === -1 || atIndex === 0 || atIndex === trimmed.length - 1) {
    return { valid: false, error: 'Email must contain local-part and domain separated by @' };
  }
  const local = trimmed.substring(0, atIndex);
  const domain = trimmed.substring(atIndex + 1);

  if (local.length > 64) {
    return { valid: false, error: 'Local-part exceeds 64 characters limit' };
  }
  if (domain.length > 253) {
    return { valid: false, error: 'Domain part exceeds 253 characters limit' };
  }
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
    return { valid: false, error: 'Local-part cannot start/end with dot or contain consecutive dots' };
  }

  const localRegex = /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+$/;
  if (!localRegex.test(local)) {
    return { valid: false, error: 'Local-part contains characters not allowed by RFC 5322' };
  }
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) {
    return { valid: false, error: 'Domain cannot start/end with dot or contain consecutive dots' };
  }

  const domainLabels = domain.split('.');
  if (domainLabels.length < 2) {
    return { valid: false, error: 'Domain must contain at least one dot separating name and TLD' };
  }

  for (const label of domainLabels) {
    if (!label || label.length > 63) {
      return { valid: false, error: 'Domain label length must be between 1 and 63 characters' };
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return { valid: false, error: 'Domain label cannot start or end with hyphen' };
    }
    if (!/^[a-z0-9-]+$/.test(label)) {
      return { valid: false, error: 'Domain label contains invalid characters' };
    }
  }

  const tld = domainLabels[domainLabels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld)) {
    return { valid: false, error: 'Top-level domain must be at least 2 alphabetic characters' };
  }

  return { valid: true, local, domain, normalized: `${local}@${domain}` };
}

async function queryCloudflareDoh(name, type) {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
    const response = await fetch(url, {
      headers: { Accept: 'application/dns-json' },
      cf: { cacheTtl: 300, cacheEverything: true },
    });
    if (!response.ok) return { Status: response.status, Answer: [] };
    return await response.json();
  } catch {
    return { Status: 2, Answer: [] };
  }
}

function cleanDnsText(raw) {
  if (!raw) return '';
  return raw.replace(/^["\s]+|["\s]+$/g, '').replace(/""/g, '');
}

function parseMxRecords(answers) {
  if (!Array.isArray(answers)) return [];
  const records = [];
  for (const ans of answers) {
    if (ans.type === 15 && typeof ans.data === 'string') {
      const parts = ans.data.trim().split(/\s+/);
      if (parts.length >= 2) {
        const priority = parseInt(parts[0], 10);
        let exchange = parts[1].toLowerCase();
        if (exchange.endsWith('.')) exchange = exchange.slice(0, -1);
        if (!isNaN(priority) && exchange) {
          records.push({ priority, exchange });
        }
      }
    }
  }
  records.sort((a, b) => a.priority - b.priority);
  return records;
}

function parseSpf(raw) {
  if (!raw) return null;
  const text = cleanDnsText(raw);
  const match = text.match(/v=spf1\b(.*)/i);
  if (!match) return null;
  const body = match[1].trim();
  let policy = 'none';
  if (/(-all)\b/i.test(body)) policy = 'fail';
  else if (/(~all)\b/i.test(body)) policy = 'softfail';
  else if (/(\?all)\b/i.test(body)) policy = 'neutral';
  else if (/(\+all)\b/i.test(body)) policy = 'pass';
  return {
    raw: text,
    policy,
    is_strict: policy === 'fail',
    is_insecure: policy === 'pass',
  };
}

function parseDmarc(raw) {
  if (!raw) return null;
  const text = cleanDnsText(raw);
  if (!/v=DMARC1\b/i.test(text)) return null;
  const pMatch = text.match(/\bp=([a-z]+)/i);
  const spMatch = text.match(/\bsp=([a-z]+)/i);
  const pctMatch = text.match(/\bpct=(\d+)/i);
  return {
    raw: text,
    policy: pMatch ? pMatch[1].toLowerCase() : 'none',
    subdomain_policy: spMatch ? spMatch[1].toLowerCase() : null,
    percentage: pctMatch ? parseInt(pctMatch[1], 10) : 100,
  };
}

async function analyzeEmail(email) {
  const startTime = performance.now();
  const syntaxCheck = validateRfc5322Syntax(email);
  if (!syntaxCheck.valid) {
    return {
      email,
      user: null,
      domain: null,
      syntax: {
        valid: false,
        error: syntaxCheck.error,
        format: 'rfc5322',
      },
      deliverability: {
        verdict: 'undeliverable',
        status: 'invalid_syntax',
        score: 0,
      },
      fraud_risk: {
        score: 100,
        level: 'critical',
        factors: ['INVALID_SYNTAX'],
      },
      domain_details: null,
      execution_time_ms: Math.round(performance.now() - startTime),
    };
  }

  const { local, domain, normalized } = syntaxCheck;
  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  const isFreeProvider = FREE_EMAIL_DOMAINS.has(domain);
  const localBase = local.split('+')[0];
  const isRoleAccount = ROLE_ACCOUNTS.has(local) || ROLE_ACCOUNTS.has(localBase);

  const [mxRes, txtRes, dmarcRes, aRes] = await Promise.all([
    queryCloudflareDoh(domain, 'MX'),
    queryCloudflareDoh(domain, 'TXT'),
    queryCloudflareDoh(`_dmarc.${domain}`, 'TXT'),
    queryCloudflareDoh(domain, 'A'),
  ]);

  const mxRecords = parseMxRecords(mxRes?.Answer);
  const txtAnswers = (txtRes?.Answer || []).filter(a => a.type === 16).map(a => a.data);
  const rawSpf = txtAnswers.find(d => d.includes('v=spf1')) || null;
  const spfRecord = parseSpf(rawSpf);

  const dmarcAnswers = (dmarcRes?.Answer || []).filter(a => a.type === 16).map(a => a.data);
  const rawDmarc = dmarcAnswers.find(d => /v=DMARC1/i.test(d)) || null;
  const dmarcRecord = parseDmarc(rawDmarc);

  const aRecords = (aRes?.Answer || []).filter(a => a.type === 1).map(a => a.data);
  const hasMxRecords = mxRecords.length > 0;
  const hasARecords = aRecords.length > 0;
  const fallbackAUsed = !hasMxRecords && hasARecords;

  let riskScore = 0;
  const factors = [];

  if (isDisposable) {
    riskScore += 85;
    factors.push('DISPOSABLE_EMAIL_PROVIDER');
  }

  if (!hasMxRecords && !hasARecords) {
    riskScore += 80;
    factors.push('NO_MAIL_SERVER_OR_DNS_RECORDS');
  } else if (fallbackAUsed) {
    riskScore += 15;
    factors.push('FALLBACK_A_RECORD_ONLY_NO_EXPLICIT_MX');
  }

  if (isRoleAccount) {
    riskScore += 15;
    factors.push('ROLE_BASED_ACCOUNT');
  }

  if (hasMxRecords) {
    if (!spfRecord) {
      riskScore += 15;
      factors.push('MISSING_SPF_RECORD');
    } else if (spfRecord.is_insecure) {
      riskScore += 20;
      factors.push('INSECURE_PERMISSIVE_SPF_PLUS_ALL');
    } else if (!spfRecord.is_strict) {
      riskScore += 5;
      factors.push('SOFTFAIL_SPF_RECORD');
    }

    if (!dmarcRecord) {
      riskScore += 15;
      factors.push('MISSING_DMARC_RECORD');
    } else if (dmarcRecord.policy === 'none') {
      riskScore += 5;
      factors.push('DMARC_POLICY_NONE');
    }
  }

  if (isFreeProvider) {
    factors.push('FREE_MAIL_PROVIDER');
  }

  riskScore = Math.min(100, Math.max(0, riskScore));

  let riskLevel = 'low';
  if (riskScore >= 85) riskLevel = 'critical';
  else if (riskScore >= 60) riskLevel = 'high';
  else if (riskScore >= 25) riskLevel = 'medium';

  let verdict = 'deliverable';
  if (isDisposable) {
    verdict = 'disposable';
  } else if (!hasMxRecords && !hasARecords) {
    verdict = 'undeliverable';
  } else if (riskScore >= 70) {
    verdict = 'undeliverable';
  } else if (riskScore >= 25 || isRoleAccount) {
    verdict = 'risky';
  }

  const deliverabilityScore = Math.max(0, 100 - riskScore);

  return {
    email: normalized,
    user: local,
    domain,
    syntax: {
      valid: true,
      format: 'rfc5322',
      local_part_length: local.length,
      domain_length: domain.length,
    },
    deliverability: {
      verdict,
      status: verdict === 'deliverable' ? 'valid' : (verdict === 'risky' ? 'acceptable' : 'invalid'),
      score: deliverabilityScore,
    },
    fraud_risk: {
      score: riskScore,
      level: riskLevel,
      factors,
    },
    domain_details: {
      is_disposable: isDisposable,
      is_free_provider: isFreeProvider,
      is_role_account: isRoleAccount,
      has_mx_records: hasMxRecords,
      mx_records: mxRecords,
      fallback_a_record_used: fallbackAUsed,
      spf: spfRecord ? {
        has_record: true,
        raw: spfRecord.raw,
        policy: spfRecord.policy,
        is_strict: spfRecord.is_strict,
      } : {
        has_record: false,
        raw: null,
        policy: null,
        is_strict: false,
      },
      dmarc: dmarcRecord ? {
        has_record: true,
        raw: dmarcRecord.raw,
        policy: dmarcRecord.policy,
        subdomain_policy: dmarcRecord.subdomain_policy,
        percentage: dmarcRecord.percentage,
      } : {
        has_record: false,
        raw: null,
        policy: null,
        subdomain_policy: null,
        percentage: 0,
      },
    },
    execution_time_ms: Math.round(performance.now() - startTime),
  };
}

export default {
  async fetch(request, env) {
    const startTime = performance.now();

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const expectedSecret = env.RAPIDAPI_PROXY_SECRET;
    if (expectedSecret) {
      const incomingSecret = request.headers.get('X-RapidAPI-Proxy-Secret');
      if (incomingSecret !== expectedSecret) {
        return jsonResponse({
          error: 'Unauthorized',
          message: 'Invalid or missing RapidAPI proxy secret.',
        }, 403);
      }
    }

    const url = new URL(request.url);

    if (url.pathname === '/' || url.pathname === '/v1/health') {
      return jsonResponse({
        status: 'healthy',
        service: 'Email Verification, Disposable Domain, MX/SPF/DMARC & Fraud Risk Scoring API',
        version: '1.0.0',
        disposable_domains_loaded: DISPOSABLE_DOMAINS.size,
        edgeRegion: request.cf?.colo || 'UNKNOWN',
        timestamp: new Date().toISOString(),
      }, 200);
    }

    if (url.pathname === '/v1/verify-batch') {
      if (request.method !== 'POST') {
        return jsonResponse({ error: 'Method Not Allowed', message: 'Only POST supported on /v1/verify-batch' }, 405);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse({ error: 'Bad Request', message: 'Malformed JSON payload.' }, 400);
      }

      if (!body || !Array.isArray(body.emails) || body.emails.length === 0 || body.emails.length > 50) {
        return jsonResponse({
          error: 'Bad Request',
          message: 'Provide a non-empty "emails" array of at most 50 emails.',
        }, 400);
      }

      const results = await Promise.all(body.emails.map(email => analyzeEmail(email)));
      let deliverable = 0;
      let risky = 0;
      let undeliverable = 0;
      let disposable = 0;
      let totalRisk = 0;

      for (const res of results) {
        totalRisk += res.fraud_risk.score;
        switch (res.deliverability.verdict) {
          case 'deliverable': deliverable++; break;
          case 'risky': risky++; break;
          case 'undeliverable': undeliverable++; break;
          case 'disposable': disposable++; break;
        }
      }

      return jsonResponse({
        total: results.length,
        deliverable,
        risky,
        undeliverable,
        disposable,
        average_risk_score: Math.round((totalRisk / results.length) * 10) / 10,
        results,
        execution_time_ms: Math.round(performance.now() - startTime),
      }, 200);
    }

    if (url.pathname === '/v1/verify') {
      let targetEmail = '';
      if (request.method === 'GET') {
        targetEmail = url.searchParams.get('email') || '';
      } else if (request.method === 'POST') {
        try {
          const body = await request.json();
          targetEmail = body.email || '';
        } catch {
          return jsonResponse({ error: 'Bad Request', message: 'Malformed JSON payload.' }, 400);
        }
      } else {
        return jsonResponse({ error: 'Method Not Allowed', message: 'Only GET and POST supported on /v1/verify' }, 405);
      }

      if (!targetEmail) {
        return jsonResponse({
          error: 'Bad Request',
          message: 'Missing required parameter: "email". Example: /v1/verify?email=user@example.com',
        }, 400);
      }

      const result = await analyzeEmail(targetEmail);
      return jsonResponse(result, 200);
    }

    return jsonResponse({
      error: 'Not Found',
      message: 'Unknown endpoint. Available routes: /v1/verify (GET/POST), /v1/verify-batch (POST), /v1/health (GET).',
    }, 404);
  },
};
