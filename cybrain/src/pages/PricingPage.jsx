import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Check, X, Zap, Shield, Crown } from 'lucide-react';

const PLANS = {
    monthly: [
        {
            id: 'free',
            name: 'Free',
            subtitle: 'For students & learners',
            price: 0,
            currency: 'DA',
            period: '/month',
            color: 'cyan',
            icon: Zap,
            badge: null,
            cta: 'Get Started Free',
            ctaLink: '/',
            highlight: false,
            limits: {
                webScans:     '5 scans/day',
                apacheScans:  '10 scans/day',
                codeScans:    '3 files/day',
                networkScans: '2 scans/day',
                aiChat:       '20 messages/day',
                reports:      'Basic MD report',
                fixes:        '3 AI fixes/day',
                history:      '7 days',
                support:      'Community',
            },
            features: [
                { text: '5 web vulnerability scans/day',    included: true  },
                { text: '10 Apache config scans/day',       included: true  },
                { text: '3 code file analyses/day',         included: true  },
                { text: '2 network scans/day',              included: true  },
                { text: 'OWASP Top 10 detection',           included: true  },
                { text: '20 AI chat messages/day',          included: true  },
                { text: 'Basic vulnerability reports (MD)', included: true  },
                { text: '3 AI-powered fixes/day',           included: true  },
                { text: '7-day scan history',               included: true  },
                { text: 'PDF report export',                included: false },
                { text: 'Unlimited scans',                  included: false },
                { text: 'API access',                       included: false },
                { text: 'Priority support',                 included: false },
                { text: 'Custom scan profiles',             included: false },
                { text: 'Team collaboration',               included: false },
            ],
        },
        {
            id: 'pro',
            name: 'Pro',
            subtitle: 'For security professionals',
            price: 19000,
            currency: 'DA',
            period: '/month',
            color: 'purple',
            icon: Shield,
            badge: 'Most Popular',
            cta: 'Start Pro Trial',
            ctaLink: '#',
            highlight: true,
            limits: {
                webScans:     'Unlimited',
                apacheScans:  'Unlimited',
                codeScans:    'Unlimited',
                networkScans: '20 scans/day',
                aiChat:       'Unlimited',
                reports:      'MD + CSV + PDF',
                fixes:        'Unlimited AI fixes',
                history:      '90 days',
                support:      'Email 24h',
            },
            features: [
                { text: 'Unlimited web vulnerability scans', included: true },
                { text: 'Unlimited Apache config scans',     included: true },
                { text: 'Unlimited code file analyses',      included: true },
                { text: '20 network scans/day',              included: true },
                { text: 'Full OWASP Top 10 + extras',        included: true },
                { text: 'Unlimited AI chat',                 included: true },
                { text: 'Full reports (MD + CSV + PDF)',     included: true },
                { text: 'Unlimited AI-powered fixes',        included: true },
                { text: '90-day scan history',               included: true },
                { text: 'PDF report export',                 included: true },
                { text: 'REST API access (500 req/day)',     included: true },
                { text: 'Priority email support',            included: true },
                { text: 'Custom scan profiles',              included: true },
                { text: 'Scheduled scans',                   included: true },
                { text: 'Team collaboration',                included: false },
            ],
        },
        {
            id: 'enterprise',
            name: 'Enterprise',
            subtitle: 'For teams & organizations',
            price: 79000,
            currency: 'DA',
            period: '/month',
            color: 'amber',
            icon: Crown,
            badge: 'Best Value',
            cta: 'Contact Sales',
            ctaLink: 'mailto:contact@cybrain.security',
            highlight: false,
            limits: {
                webScans:     'Unlimited',
                apacheScans:  'Unlimited',
                codeScans:    'Unlimited',
                networkScans: 'Unlimited',
                aiChat:       'Unlimited',
                reports:      'All formats + custom',
                fixes:        'Unlimited AI fixes',
                history:      '1 year',
                support:      'Dedicated engineer',
            },
            features: [
                { text: 'Everything in Pro',                    included: true },
                { text: 'Unlimited network scans',              included: true },
                { text: 'Unlimited API access',                 included: true },
                { text: 'Custom report branding',               included: true },
                { text: '1-year scan history',                  included: true },
                { text: 'Team collaboration (up to 20 users)',  included: true },
                { text: 'SSO / SAML integration',               included: true },
                { text: 'Dedicated security engineer',          included: true },
                { text: 'SLA 99.9% uptime guarantee',           included: true },
                { text: 'On-premise deployment option',         included: true },
                { text: 'Custom vulnerability rules',           included: true },
                { text: 'CI/CD pipeline integration',           included: true },
                { text: 'Compliance reports (GDPR/PCI/ISO)',    included: true },
                { text: 'White-label option',                   included: true },
                { text: 'Phone + Slack support',                included: true },
            ],
        },
    ],
};

// Annual plans = 2 months free (×10 instead of ×12)
const getAnnualPrice = (monthly) =>
    monthly === 0 ? 0 : monthly * 10;

const COLOR_MAP = {
    cyan: {
        badge:      'bg-cyan-500/20 text-cyan-400 border-cyan-500/40',
        button:     'border-cyan-500/50 text-cyan-400 hover:bg-cyan-500 hover:text-black',
        icon:       'bg-cyan-500/20 text-cyan-400',
        check:      'text-cyan-400',
        glow:       'shadow-cyan-500/10',
        border:     'border-cyan-500/20',
        highlight:  false,
    },
    purple: {
        badge:      'bg-purple-500/20 text-purple-400 border-purple-500/40',
        button:     'bg-purple-500 text-white hover:bg-purple-400 border-transparent',
        icon:       'bg-purple-500/20 text-purple-400',
        check:      'text-purple-400',
        glow:       'shadow-purple-500/20',
        border:     'border-purple-500/40',
        highlight:  true,
    },
    amber: {
        badge:      'bg-amber-500/20 text-amber-400 border-amber-500/40',
        button:     'border-amber-500/50 text-amber-400 hover:bg-amber-500 hover:text-black',
        icon:       'bg-amber-500/20 text-amber-400',
        check:      'text-amber-400',
        glow:       'shadow-amber-500/10',
        border:     'border-amber-500/20',
        highlight:  false,
    },
};

const PricingPage = () => {
    const [billing, setBilling] = useState('monthly');

    const plans = PLANS.monthly;

    return (
        <div className="min-h-screen bg-black
                        content-section pt-[72px]
                        pb-24 overflow-x-hidden">
            <div className="max-w-7xl mx-auto
                            px-4 md:px-6 lg:px-12">

                {/* ── HEADER ──────────────────────── */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-center py-16 md:py-24"
                >
                    <p className="font-orbitron text-xs
                                  tracking-[0.4em] uppercase
                                  text-cyan-500/60 mb-4">
                        Simple Pricing
                    </p>
                    <h1 className="font-orbitron font-black
                                   text-3xl md:text-5xl
                                   text-white tracking-wider
                                   mb-4">
                        CHOOSE YOUR{' '}
                        <span className="text-cyan-400">
                            PLAN
                        </span>
                    </h1>
                    <p className="text-gray-500 font-inter
                                  text-sm md:text-base
                                  max-w-xl mx-auto mb-10">
                        Start free. Upgrade when you need
                        more power. All plans include our
                        core security detection engine.
                    </p>

                    {/* Billing Toggle */}
                    <div className="inline-flex items-center
                                    gap-1 scanner-glass
                                    rounded-full p-1">
                        <button
                            onClick={() =>
                                setBilling('monthly')
                            }
                            className={`px-5 py-2 rounded-full
                                font-orbitron text-xs
                                tracking-widest uppercase
                                transition-all duration-300
                                ${billing === 'monthly'
                                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                                    : 'text-gray-500 hover:text-gray-300'
                                }`}
                        >
                            Monthly
                        </button>
                        <button
                            onClick={() =>
                                setBilling('annual')
                            }
                            className={`px-5 py-2 rounded-full
                                font-orbitron text-xs
                                tracking-widest uppercase
                                transition-all duration-300
                                flex items-center gap-2
                                ${billing === 'annual'
                                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                                    : 'text-gray-500 hover:text-gray-300'
                                }`}
                        >
                            Annual
                            <span className="text-[10px]
                                             bg-green-500/20
                                             text-green-400
                                             border
                                             border-green-500/30
                                             px-2 py-0.5
                                             rounded-full">
                                -17%
                            </span>
                        </button>
                    </div>

                    {billing === 'annual' && (
                        <motion.p
                            initial={{ opacity: 0, y: -5 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="text-green-400/70
                                       text-xs font-inter
                                       mt-3"
                        >
                            ✓ 2 months free with annual billing
                        </motion.p>
                    )}
                </motion.div>

                {/* ── PRICING CARDS ───────────────── */}
                <div className="grid grid-cols-1
                                md:grid-cols-3 gap-6
                                md:gap-4 lg:gap-6
                                items-start">
                    {plans.map((plan, index) => {
                        const colors = COLOR_MAP[plan.color];
                        const Icon   = plan.icon;
                        const price  = billing === 'annual'
                            ? getAnnualPrice(plan.price)
                            : plan.price;
                        const period = billing === 'annual'
                            ? '/year'
                            : '/month';

                        return (
                            <motion.div
                                key={plan.id}
                                initial={{
                                    opacity: 0,
                                    y: 30
                                }}
                                animate={{
                                    opacity: 1,
                                    y: 0
                                }}
                                transition={{
                                    delay: index * 0.1
                                }}
                                className={`
                                    relative rounded-2xl
                                    border p-6 md:p-8
                                    flex flex-col
                                    transition-all duration-300
                                    ${colors.border}
                                    ${colors.highlight
                                        ? `shadow-2xl ${colors.glow} scale-100 md:scale-105`
                                        : 'hover:border-opacity-60'
                                    }
                                `}
                                style={{
                                    background: colors.highlight
                                        ? 'rgba(168,85,247,0.05)'
                                        : 'rgba(255,255,255,0.02)',
                                    backdropFilter: 'blur(20px)',
                                }}
                            >
                                {/* Popular badge */}
                                {plan.badge && (
                                    <div className={`
                                        absolute -top-3
                                        left-1/2 -translate-x-1/2
                                        px-4 py-1 rounded-full
                                        text-[10px] font-orbitron
                                        font-bold tracking-widest
                                        uppercase border
                                        whitespace-nowrap
                                        ${colors.badge}
                                    `}>
                                        {plan.badge}
                                    </div>
                                )}

                                {/* Plan header */}
                                <div className="mb-6">
                                    <div className={`
                                        w-10 h-10 rounded-xl
                                        flex items-center
                                        justify-center mb-4
                                        ${colors.icon}
                                    `}>
                                        <Icon size={20} />
                                    </div>

                                    <h2 className="font-orbitron
                                                   font-black
                                                   text-xl
                                                   text-white
                                                   tracking-wider
                                                   mb-1">
                                        {plan.name}
                                    </h2>
                                    <p className="text-gray-500
                                                  text-xs
                                                  font-inter">
                                        {plan.subtitle}
                                    </p>
                                </div>

                                {/* Price */}
                                <div className="mb-6 pb-6
                                                border-b
                                                border-white/5">
                                    <div className="flex items-end
                                                    gap-1">
                                        <span className="text-gray-500
                                                         text-lg
                                                         font-orbitron
                                                         mb-1">
                                            {plan.currency}
                                        </span>
                                        <motion.span
                                            key={`${plan.id}-${billing}`}
                                            initial={{
                                                opacity: 0,
                                                y: -10
                                            }}
                                            animate={{
                                                opacity: 1,
                                                y: 0
                                            }}
                                            className="font-orbitron
                                                       font-black
                                                       text-4xl
                                                       md:text-5xl
                                                       text-white"
                                        >
                                            {price === 0 ? '0' : price.toLocaleString()}
                                        </motion.span>
                                        <span className="text-gray-500
                                                         text-sm
                                                         font-inter
                                                         mb-2">
                                            {price === 0
                                                ? '/forever'
                                                : period}
                                        </span>
                                    </div>

                                    {billing === 'annual' &&
                                        plan.price > 0 && (
                                        <p className="text-gray-600
                                                      text-xs
                                                      font-inter mt-1">
                                            {plan.price.toLocaleString()} DA/mo
                                            billed annually
                                        </p>
                                    )}
                                </div>

                                {/* Limits summary */}
                                <div className="mb-6 space-y-2">
                                    {Object.entries(
                                        plan.limits
                                    ).map(([key, val]) => (
                                        <div key={key}
                                             className="flex
                                                        items-center
                                                        justify-between
                                                        text-xs">
                                            <span className="text-gray-500
                                                             font-inter
                                                             capitalize">
                                                {key.replace(
                                                    /([A-Z])/g,
                                                    ' $1'
                                                )}
                                            </span>
                                            <span className={`
                                                font-orbitron
                                                font-bold
                                                tracking-wide
                                                ${val === 'Unlimited'
                                                    ? colors.check
                                                    : 'text-gray-300'
                                                }
                                            `}>
                                                {val}
                                            </span>
                                        </div>
                                    ))}
                                </div>

                                {/* CTA Button */}
                                <a
                                    href={plan.ctaLink}
                                    className={`
                                        w-full py-3 mb-6
                                        font-orbitron font-bold
                                        text-xs tracking-[0.2em]
                                        uppercase rounded-xl
                                        border text-center
                                        transition-all duration-300
                                        block
                                        ${colors.button}
                                    `}
                                >
                                    {plan.cta}
                                </a>

                                {/* Features list */}
                                <div className="space-y-3
                                                flex-1">
                                    {plan.features.map(
                                        (f, i) => (
                                        <div key={i}
                                             className="flex
                                                        items-start
                                                        gap-3">
                                            {f.included ? (
                                                <Check
                                                    size={14}
                                                    className={`
                                                        flex-shrink-0
                                                        mt-0.5
                                                        ${colors.check}
                                                    `}
                                                />
                                            ) : (
                                                <X
                                                    size={14}
                                                    className="flex-shrink-0
                                                               mt-0.5
                                                               text-gray-700"
                                                />
                                            )}
                                            <span className={`
                                                text-xs
                                                font-inter
                                                leading-relaxed
                                                ${f.included
                                                    ? 'text-gray-400'
                                                    : 'text-gray-700'
                                                }
                                            `}>
                                                {f.text}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            </motion.div>
                        );
                    })}
                </div>

                {/* ── COMPARISON TABLE ────────────── */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.5 }}
                    className="mt-24"
                >
                    <h2 className="font-orbitron font-black
                                   text-2xl md:text-3xl
                                   text-white text-center
                                   tracking-wider mb-12">
                        FULL{' '}
                        <span className="text-cyan-400">
                            COMPARISON
                        </span>
                    </h2>

                    <div className="overflow-x-auto
                                    rounded-2xl
                                    scanner-glass">
                        <table className="w-full
                                          min-w-[640px]">
                            <thead>
                                <tr className="border-b
                                               border-white/5">
                                    <th className="text-left
                                                   p-4 md:p-6
                                                   font-orbitron
                                                   text-xs
                                                   text-gray-500
                                                   tracking-widest
                                                   uppercase
                                                   w-1/2">
                                        Feature
                                    </th>
                                    {['Free','Pro',
                                      'Enterprise'].map(
                                        (p, i) => (
                                        <th key={p}
                                            className={`
                                            p-4 md:p-6
                                            font-orbitron
                                            text-xs
                                            tracking-widest
                                            uppercase
                                            text-center
                                            ${i === 1
                                                ? 'text-purple-400'
                                                : i === 2
                                                ? 'text-amber-400'
                                                : 'text-cyan-400'
                                            }
                                        `}>
                                            {p}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {[
                                    ['Web Scans',         '5/day',    'Unlimited', 'Unlimited'],
                                    ['Apache Scans',      '10/day',   'Unlimited', 'Unlimited'],
                                    ['Code Analysis',     '3/day',    'Unlimited', 'Unlimited'],
                                    ['Network Scans',     '2/day',    '20/day',    'Unlimited'],
                                    ['AI Chat',           '20 msg/day','Unlimited','Unlimited'],
                                    ['AI Code Fixes',     '3/day',    'Unlimited', 'Unlimited'],
                                    ['Report Formats',    'MD',       'MD+CSV+PDF','All+Custom'],
                                    ['Scan History',      '7 days',   '90 days',  '1 year'],
                                    ['API Access',        '✗',        '500 req/d', 'Unlimited'],
                                    ['Scheduled Scans',   '✗',        '✓',        '✓'],
                                    ['Team Members',      '1',        '1',        'Up to 20'],
                                    ['Custom Rules',      '✗',        '✓',        '✓'],
                                    ['SSO / SAML',        '✗',        '✗',        '✓'],
                                    ['Compliance Reports','✗',        '✗',        '✓'],
                                    ['White Label',       '✗',        '✗',        '✓'],
                                    ['Support',           'Community','Email 24h', 'Dedicated'],
                                    ['SLA',               '✗',        '99%',      '99.9%'],
                                     ['Price',             '0 DA',     '19,000 DA/mo','79,000 DA/mo'],
                                ].map((row, i) => (
                                    <tr key={i}
                                        className={`
                                            border-b
                                            border-white/5
                                            transition-colors
                                            hover:bg-white/2
                                            ${i % 2 === 0
                                                ? ''
                                                : 'bg-white/[0.01]'
                                            }
                                        `}
                                    >
                                        <td className="p-4
                                                       text-gray-400
                                                       text-xs
                                                       font-inter">
                                            {row[0]}
                                        </td>
                                        {row.slice(1).map(
                                            (val, j) => (
                                            <td key={j}
                                                className={`
                                                p-4 text-xs
                                                text-center
                                                font-orbitron
                                                tracking-wide
                                                ${val === '✓'
                                                    ? j === 1
                                                        ? 'text-purple-400'
                                                        : 'text-amber-400'
                                                    : val === '✗'
                                                    ? 'text-gray-700'
                                                    : j === 0
                                                    ? 'text-cyan-400/80'
                                                    : j === 1
                                                    ? 'text-purple-400/80'
                                                    : 'text-amber-400/80'
                                                }
                                            `}>
                                                {val}
                                            </td>
                                        ))}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </motion.div>

                {/* ── FAQ ─────────────────────────── */}
                <div className="mt-24 max-w-3xl mx-auto">
                    <h2 className="font-orbitron font-black
                                   text-2xl text-white
                                   text-center tracking-wider
                                   mb-12">
                        FREQUENTLY ASKED{' '}
                        <span className="text-cyan-400">
                            QUESTIONS
                        </span>
                    </h2>
                    <div className="space-y-4">
                        {[
                            {
                                q: 'Is the free plan really free forever?',
                                a: 'Yes. The Free plan has no time limit and no credit card required. You get 5 web scans, 10 Apache scans, and 3 code analyses per day — more than enough for students and personal projects.',
                            },
                            {
                                q: 'What happens when I hit the daily limit?',
                                a: 'Your scan counter resets every 24 hours at midnight UTC. If you need more scans immediately, you can upgrade to Pro at any time and the new limits apply instantly.',
                            },
                            {
                                q: 'Can I cancel my subscription anytime?',
                                a: 'Absolutely. No contracts, no cancellation fees. Cancel from your account settings and you keep access until the end of your billing period.',
                            },
                            {
                                q: 'Is my scan data private and secure?',
                                a: 'Yes. All scans are processed securely. Scan results are stored encrypted and only accessible by your account. We never share your data with third parties.',
                            },
                            {
                                q: 'What is the difference between the Pro API and Enterprise API?',
                                a: 'Pro includes 500 API requests per day suitable for individual developers and CI/CD pipelines. Enterprise includes unlimited API access with SLA guarantees and dedicated rate limits.',
                            },
                            {
                                q: 'Do you offer student or academic discounts?',
                                a: 'Yes! Students and academic researchers get 50% off Pro with a valid .edu email address. Contact us at contact@cybrain.security with proof of enrollment.',
                            },
                        ].map((faq, i) => (
                            <FaqItem
                                key={i}
                                question={faq.q}
                                answer={faq.a}
                            />
                        ))}
                    </div>
                </div>

                {/* ── FOOTER CTA ──────────────────── */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.8 }}
                    className="mt-24 text-center
                               scanner-glass rounded-2xl
                               p-12 md:p-16"
                >
                    <h2 className="font-orbitron font-black
                                   text-2xl md:text-3xl
                                   text-white tracking-wider
                                   mb-4">
                        READY TO SECURE YOUR{' '}
                        <span className="text-cyan-400">
                            INFRASTRUCTURE?
                        </span>
                    </h2>
                    <p className="text-gray-500 font-inter
                                  text-sm mb-8 max-w-md
                                  mx-auto">
                        Start with the free plan today.
                        No credit card required.
                        Upgrade anytime.
                    </p>
                    <div className="flex flex-wrap
                                    items-center
                                    justify-center gap-4">
                        <a href="/"
                           className="px-8 py-3
                                      bg-cyan-500/10
                                      border border-cyan-500/50
                                      text-cyan-400
                                      font-orbitron font-bold
                                      text-xs tracking-[0.2em]
                                      uppercase rounded-xl
                                      hover:bg-cyan-500
                                      hover:text-black
                                      transition-all">
                            Start Free →
                        </a>
                        <a
                            href="mailto:contact@cybrain.security"
                            className="px-8 py-3 border
                                       border-white/10
                                       text-gray-400
                                       font-orbitron text-xs
                                       tracking-[0.2em]
                                       uppercase rounded-xl
                                       hover:border-white/30
                                       hover:text-white
                                       transition-all">
                            Contact Sales
                        </a>
                    </div>
                </motion.div>

            </div>
        </div>
    );
};

// FAQ accordion item
const FaqItem = ({ question, answer }) => {
    const [open, setOpen] = useState(false);
    return (
        <div className="scanner-glass rounded-xl
                        overflow-hidden">
            <button
                onClick={() => setOpen(!open)}
                className="w-full p-5 flex items-center
                           justify-between text-left
                           hover:bg-white/[0.02]
                           transition-colors"
            >
                <span className="font-inter text-sm
                                 text-gray-300
                                 font-medium pr-4">
                    {question}
                </span>
                <motion.span
                    animate={{ rotate: open ? 45 : 0 }}
                    className="text-cyan-400 text-xl
                               flex-shrink-0 font-light"
                >
                    +
                </motion.span>
            </button>
            <motion.div
                initial={false}
                animate={{
                    height: open ? 'auto' : 0,
                    opacity: open ? 1 : 0,
                }}
                transition={{ duration: 0.3 }}
                style={{ overflow: 'hidden' }}
            >
                <p className="px-5 pb-5 text-gray-500
                              text-sm font-inter
                              leading-relaxed">
                    {answer}
                </p>
            </motion.div>
        </div>
    );
};

export default PricingPage;
