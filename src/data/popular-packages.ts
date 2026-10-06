/**
 * Well-known npm package names (offline, no registry lookups). Names that exist on npm only as
 * unrelated stubs or abandoned packages (swc, nestjs, biome, ...) are deliberately absent.
 * Used for typosquat / slopsquat heuristics: a dependency that is NOT in this list but is
 * one or two characters away from a name that is, deserves a second look.
 * The list does not need to be exhaustive; it only needs to contain the names attackers imitate.
 */
const RAW = `
react react-dom react-native react-router react-router-dom react-redux react-query react-hook-form
react-select react-table react-icons react-scripts react-is react-test-renderer react-transition-group
react-helmet react-helmet-async react-toastify react-hot-toast react-dropzone react-datepicker
react-markdown react-syntax-highlighter react-virtualized react-window react-use react-spring
react-i18next react-error-boundary react-intersection-observer react-day-picker react-resizable-panels
react-textarea-autosize react-remove-scroll react-style-singleton react-refresh react-chartjs-2
react-big-calendar react-beautiful-dnd react-dnd react-native-web react-native-svg react-native-reanimated
react-native-gesture-handler react-native-screens react-native-safe-area-context
next next-auth next-themes next-intl next-seo next-sitemap next-transpile-modules nextra
preact vue vue-router vuex pinia nuxt svelte solid-js
@angular/core @angular/common @angular/compiler @angular/forms @angular/router @angular/cli
@angular/platform-browser @angular/animations @angular/material @angular/cdk
@supabase/supabase-js @supabase/ssr @supabase/auth-helpers-nextjs @supabase/auth-helpers-react
@supabase/auth-ui-react @supabase/auth-ui-shared @supabase/postgrest-js @supabase/gotrue-js
@supabase/realtime-js @supabase/storage-js @supabase/functions-js @supabase/node-fetch supabase
firebase firebase-admin firebase-functions firebase-tools @firebase/app @firebase/auth
stripe @stripe/stripe-js @stripe/react-stripe-js @stripe/stripe-react-native
openai @anthropic-ai/sdk @google/generative-ai @google/genai ai @ai-sdk/openai @ai-sdk/anthropic
@ai-sdk/google @ai-sdk/react langchain @langchain/core @langchain/openai @langchain/community
llamaindex cohere-ai @mistralai/mistralai replicate groq-sdk @huggingface/inference @pinecone-database/pinecone
tailwindcss postcss autoprefixer cssnano postcss-loader postcss-import postcss-nested postcss-preset-env
tailwind-merge tailwindcss-animate @tailwindcss/forms @tailwindcss/typography @tailwindcss/postcss
@tailwindcss/vite class-variance-authority clsx classnames
zod yup joi ajv ajv-formats valibot superstruct io-ts @hookform/resolvers
typescript ts-node tsx ts-jest tsup tslib ts-loader ts-morph ts-pattern ts-node-dev tsc-watch
@types/node @types/react @types/react-dom @types/jest @types/lodash @types/express @types/cors
@types/bcrypt @types/bcryptjs @types/jsonwebtoken @types/uuid @types/mocha @types/chai @types/cookie-parser
@types/body-parser @types/node-fetch @types/webpack @types/estree @types/prop-types @types/debug
@types/minimist @types/semver @types/ws @types/pg @types/mongoose @types/morgan @types/multer
@types/supertest @types/passport @types/react-native @types/js-cookie @types/lodash-es @types/glob
vite vitest @vitejs/plugin-react @vitejs/plugin-react-swc @vitejs/plugin-vue vite-plugin-pwa
vite-tsconfig-paths vite-plugin-svgr webpack webpack-cli webpack-dev-server webpack-merge
webpack-bundle-analyzer html-webpack-plugin mini-css-extract-plugin css-loader style-loader sass-loader
babel-loader file-loader url-loader copy-webpack-plugin terser-webpack-plugin
rollup @rollup/plugin-node-resolve @rollup/plugin-commonjs @rollup/plugin-typescript @rollup/plugin-json
@rollup/plugin-terser @rollup/plugin-babel rollup-plugin-terser esbuild @swc/core @swc/helpers
parcel turbo nx lerna rimraf cross-env concurrently npm-run-all npm-run-all2 nodemon pm2
@babel/core @babel/preset-env @babel/preset-react @babel/preset-typescript @babel/cli @babel/runtime
@babel/parser @babel/traverse @babel/types @babel/generator @babel/plugin-transform-runtime
@babel/register @babel/polyfill @babel/helpers @babel/code-frame @babel/template babel-jest
babel-core babel-eslint babel-plugin-styled-components core-js core-js-pure regenerator-runtime
eslint eslint-config-next eslint-config-prettier eslint-plugin-react eslint-plugin-react-hooks
eslint-plugin-import eslint-plugin-jsx-a11y eslint-plugin-prettier eslint-plugin-vue
eslint-plugin-unused-imports eslint-plugin-jest eslint-plugin-n eslint-plugin-promise
eslint-plugin-security eslint-plugin-tailwindcss eslint-plugin-testing-library eslint-config-airbnb
eslint-config-standard eslint-config-turbo eslint-scope eslint-utils eslint-visitor-keys
@eslint/js @eslint/eslintrc @typescript-eslint/parser @typescript-eslint/eslint-plugin
@typescript-eslint/utils @typescript-eslint/typescript-estree typescript-eslint
prettier prettier-plugin-tailwindcss stylelint husky lint-staged commitlint @commitlint/cli
@commitlint/config-conventional standard xo @biomejs/biome oxlint
jest jest-environment-jsdom jest-environment-node jest-cli jest-mock jest-util
@jest/globals @jest/core @jest/types mocha chai chai-as-promised sinon sinon-chai supertest
ava tap tape jasmine karma cypress playwright @playwright/test puppeteer puppeteer-core
@testing-library/react @testing-library/jest-dom @testing-library/user-event @testing-library/dom
@testing-library/react-native @vitest/coverage-v8 @vitest/ui c8 nyc istanbul msw nock
express express-session express-validator express-rate-limit express-fileupload express-handlebars
koa koa-router koa-bodyparser fastify @fastify/cors @fastify/jwt @fastify/static @hapi/hapi
hono @hono/node-server elysia @nestjs/core @nestjs/common @nestjs/platform-express
@nestjs/config @nestjs/jwt @nestjs/passport @nestjs/swagger @nestjs/typeorm @nestjs/mongoose
body-parser cors helmet morgan compression cookie-parser cookie csurf serve-static connect
multer formidable busboy http-proxy-middleware http-proxy http-errors on-finished raw-body
passport passport-local passport-jwt passport-google-oauth20 passport-github2 bcrypt bcryptjs
argon2 jsonwebtoken jose jwt-decode jws jwa cookie-session iron-session oauth uuid nanoid
cuid shortid crypto-js crypto-browserify tweetnacl node-forge
axios node-fetch got ky superagent request request-promise undici isomorphic-fetch cross-fetch
whatwg-fetch swr @tanstack/react-query @tanstack/react-table @tanstack/react-router
@tanstack/react-virtual @tanstack/query-core @tanstack/table-core @tanstack/react-form
graphql graphql-tag graphql-request graphql-ws apollo-server apollo-server-express
@apollo/client @apollo/server urql @trpc/server @trpc/client @trpc/react-query @trpc/next
lodash lodash-es lodash.merge lodash.debounce lodash.throttle lodash.clonedeep lodash.get
lodash.isequal lodash.set lodash.uniq lodash.pick lodash.omit underscore ramda immer immutable
moment moment-timezone dayjs date-fns date-fns-tz luxon
chalk colors picocolors kleur ansi-colors ansi-styles ansi-regex strip-ansi wrap-ansi
supports-color color color-convert color-name color-string debug ms tinycolor2 @ctrl/tinycolor
commander yargs yargs-parser minimist meow cac inquirer prompts enquirer ora cli-progress
boxen figlet listr2 chokidar glob globby fast-glob minimatch micromatch picomatch anymatch
fs-extra graceful-fs rimraf mkdirp del make-dir tmp tmp-promise tar archiver adm-zip jszip unzipper
dotenv dotenv-expand dotenv-cli env-cmd cross-spawn execa shelljs which semver
mime mime-types mime-db iconv-lite safe-buffer buffer readable-stream through2 pump
mongoose mongodb mongodb-memory-server pg pg-promise mysql mysql2 sqlite3 better-sqlite3
sequelize typeorm knex objection prisma @prisma/client drizzle-orm drizzle-kit kysely
redis ioredis bullmq bull amqplib kafkajs nats memcached
@neondatabase/serverless @planetscale/database @libsql/client @vercel/postgres @vercel/kv
@vercel/analytics @vercel/blob @vercel/edge-config @vercel/og @vercel/speed-insights vercel
@clerk/nextjs @clerk/clerk-react @clerk/clerk-sdk-node @auth/core @auth0/auth0-react @auth0/nextjs-auth0
auth0 lucia better-auth @kinde-oss/kinde-auth-nextjs @workos-inc/node
@aws-sdk/client-s3 @aws-sdk/client-dynamodb @aws-sdk/client-ses @aws-sdk/client-sqs @aws-sdk/client-sns
@aws-sdk/client-lambda @aws-sdk/lib-dynamodb @aws-sdk/s3-request-presigner @aws-sdk/credential-providers
aws-sdk aws-cdk aws-cdk-lib constructs serverless aws-lambda @types/aws-lambda
@google-cloud/storage @google-cloud/firestore @google-cloud/pubsub googleapis google-auth-library
@azure/storage-blob @azure/identity @azure/msal-browser azure-storage
@sentry/node @sentry/react @sentry/nextjs @sentry/browser @sentry/cli @sentry/tracing
@datadog/browser-rum dd-trace newrelic winston pino pino-pretty bunyan loglevel log4js
posthog-js posthog-node mixpanel mixpanel-browser @segment/analytics-next analytics-node
resend nodemailer @sendgrid/mail mailgun.js postmark twilio @twilio/voice-sdk
@radix-ui/react-dialog @radix-ui/react-dropdown-menu @radix-ui/react-slot @radix-ui/react-tooltip
@radix-ui/react-popover @radix-ui/react-select @radix-ui/react-tabs @radix-ui/react-toast
@radix-ui/react-checkbox @radix-ui/react-label @radix-ui/react-switch @radix-ui/react-accordion
@radix-ui/react-avatar @radix-ui/react-slider @radix-ui/react-separator @radix-ui/react-scroll-area
@radix-ui/react-alert-dialog @radix-ui/react-radio-group @radix-ui/react-progress @radix-ui/react-icons
cmdk vaul sonner embla-carousel-react input-otp next-safe-action
lucide-react lucide-react-native @heroicons/react @tabler/icons-react @phosphor-icons/react
@mui/material @mui/icons-material @mui/system @mui/x-data-grid @emotion/react @emotion/styled
@emotion/css @chakra-ui/react @mantine/core @mantine/hooks @headlessui/react @nextui-org/react
antd @ant-design/icons bootstrap react-bootstrap reactstrap semantic-ui-react primereact
styled-components styled-jsx sass node-sass less stylus
framer-motion motion gsap three @react-three/fiber @react-three/drei d3 chart.js recharts victory
echarts highcharts plotly.js leaflet react-leaflet mapbox-gl @googlemaps/js-api-loader
redux @reduxjs/toolkit redux-thunk redux-saga redux-persist reselect zustand jotai recoil valtio
mobx mobx-react xstate @xstate/react rxjs
formik react-final-form final-form
i18next i18next-browser-languagedetector i18next-http-backend next-i18next react-intl
@formatjs/intl-localematcher
marked markdown-it remark remark-gfm remark-parse remark-rehype rehype-raw rehype-highlight
unified mdast-util-to-string highlight.js prismjs shiki katex mermaid
cheerio jsdom domhandler htmlparser2 parse5 sanitize-html dompurify isomorphic-dompurify xss validator
sharp jimp canvas pdfkit pdf-lib pdfjs-dist puppeteer-extra html-pdf-node
socket.io socket.io-client ws engine.io sockjs-client eventsource mqtt
event-stream eventemitter3 events inherits util assert process path-browserify stream-browserify
os-browserify url querystring qs query-string
tslog typedoc typeorm-extension reflect-metadata class-validator class-transformer inversify tsyringe
rxjs-compat zone.js tslint codelyzer webpack-node-externals source-map source-map-support
js-yaml yaml toml ini xml2js fast-xml-parser csv-parse csv-parser papaparse xlsx exceljs
json5 jsonc-parser ajv-keywords fast-json-stable-stringify fast-deep-equal deepmerge deep-equal
object-assign object-hash is-plain-object is-promise is-number is-glob is-stream is-buffer is-arrayish
has-flag has-symbols kind-of array-flatten arrify camelcase decamelize p-limit p-queue p-map p-retry
async bluebird q promise promise-polyfill p-timeout delay retry lru-cache quick-lru node-cache
cache-manager keyv conf configstore update-notifier open opn clipboardy terminal-link
body-scroll-lock focus-trap focus-trap-react tabbable popper.js @popperjs/core @floating-ui/react
@floating-ui/dom @dnd-kit/core @dnd-kit/sortable swiper slick-carousel lottie-web lottie-react
@lottiefiles/lottie-player @solana/web3.js ethers web3 viem wagmi @wagmi/core @rainbow-me/rainbowkit
@web3modal/wagmi hardhat @openzeppelin/contracts bitcoinjs-lib @ledgerhq/connect-kit
expo expo-router expo-constants expo-font expo-image expo-linking expo-secure-store expo-status-bar
expo-splash-screen expo-notifications expo-camera expo-file-system @expo/vector-icons
@react-navigation/native @react-navigation/stack @react-navigation/bottom-tabs
@react-native-async-storage/async-storage @react-native-community/netinfo
electron electron-builder electron-store electron-updater @tauri-apps/api @tauri-apps/cli
storybook @storybook/react @storybook/addon-essentials @storybook/addon-links @storybook/nextjs
@storybook/react-vite @storybook/test @storybook/blocks @storybook/addon-interactions
contentlayer next-contentlayer @mdx-js/react @mdx-js/loader @next/mdx @next/font @next/bundle-analyzer
gray-matter reading-time slugify github-slugger rss feed sitemap
uploadthing @uploadthing/react cloudinary next-cloudinary @vercel/functions
@t3-oss/env-nextjs @t3-oss/env-core superjson server-only client-only
shadcn shadcn-ui @hookform/devtools
@trigger.dev/sdk inngest @upstash/redis @upstash/ratelimit @upstash/qstash
convex @convex-dev/auth appwrite node-appwrite pocketbase
airtable notion-client @notionhq/client @slack/web-api @slack/bolt discord.js telegraf grammy
octokit @octokit/rest @octokit/core simple-git isomorphic-git
snyk npm yarn pnpm npx corepack bun
nodemon-webpack-plugin ts-essentials type-fest utility-types
`;

/** Every popular package name, lowercase. */
export const POPULAR_PACKAGES: ReadonlySet<string> = new Set(
  RAW.split(/\s+/).filter((n) => n.length > 0),
);

/** Same names as an array, for distance scans. */
export const POPULAR_LIST: readonly string[] = [...POPULAR_PACKAGES];

/**
 * Legitimate packages that look like typos of popular ones but are real, separate projects.
 * They are skipped by the typosquat check even when absent from POPULAR_PACKAGES.
 */
export const LEGIT_LOOKALIKES: ReadonlySet<string> = new Set([
  "preact", "react-dom-factories", "react-is", "reactn", "nuxt3", "vuex-persist", "vue-i18n",
  "ts-jest", "ts-node", "ts-mocha", "next-auth", "nextjs-toploader", "ejs", "pug", "hbs",
  "chalk-template", "cli-table3", "lodash.isempty", "lodash.map", "lodash.flatten", "lodash.keys",
  "lodash.values", "lodash.defaults", "lodash.merge", "mime-types", "mime-db", "qs", "q",
]);
