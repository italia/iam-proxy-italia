# Design Tokens Italia

[![Versione](https://img.shields.io/npm/v/design-tokens-italia.svg?logo=npm)](https://github.com/italia/design-tokens-italia/releases)
[![Build](https://github.com/italia/design-tokens-italia/actions/workflows/build.yml/badge.svg)](https://github.com/italia/design-tokens-italia/actions)
[![GitHub issues](https://img.shields.io/github/issues/italia/design-tokens-italia.svg)](https://github.com/italia/design-tokens-italia/issues)
[![Join the #design channel](https://img.shields.io/badge/Slack%20channel-%23design-blue.svg)](https://developersitalia.slack.com/messages/C7VPAUVB3/)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)

I design tokens del [Design system .italia](https://designers.italia.it/design-system/) definiscono, documentano e consentono l'applicazione di decisioni progettuali su larga scala, garantendo la coerenza di progettazione e sviluppo delle interfacce digitali della Pubblica Amministrazione italiana.

Rappresentano associazioni fra attributi, come colori, tipografia, spaziature e dimensioni e i loro valori. Per questo motivo sono considerati i fondamenti strutturali del design system.

Per maggiori informazioni consulta la [documentazione ufficiale](https://designers.italia.it/design-system/fondamenti/design-tokens/) del design system. 

## Installazione

Si richiede `Node >= 22`

```sh
npm install design-tokens-italia
```

## Utilizzo

### CSS Custom Properties
```css
@import 'design-tokens-italia/dist/css/variables.css';

.mio-elemento {
  color: var(--color-text-primary);
  padding: var(--spacing-md);
}
```

### Variabili Sass
```scss
@import 'design-tokens-italia/dist/scss/variables';

.mio-elemento {
  color: $color-text-primary;
  padding: $spacing-md;
}
```

## Contenuto del package

I design token sono classificati in tre livelli di profondità in base al contesto di applicazione:

- **Token globali** (`tokens/global.json`) - fondamenti visivi strutturali, usati come riferimento per i livelli semantici e specifici
- **Token semantici** (`tokens/semantic.json`) - decisioni progettuali riutilizzabili per più elementi e componenti
- **Token specifici** (`tokens/specific.json`) - rappresentazione esaustiva di ogni valore associato a un elemento o componente

I file CSS e SCSS nella cartella `dist/` sono generati automaticamente dai file JSON tramite [Style Dictionary](https://styledictionary.com/).

## Contribuire allo sviluppo

### Setup locale
```sh
npm install
```

### Workflow di aggiornamento

1. I design token vengono esportati da Figma utilizzando [Tokens Studio for Figma](https://docs.tokens.studio) in formato JSON
2. I file JSON vengono salvati nella cartella `tokens/`
3. Style Dictionary genera automaticamente le variabili CSS e SCSS:
```sh
npm run build
```

Questo comando processa i file JSON e genera:
- `dist/css/variables.css` - CSS Custom Properties
- `dist/scss/_variables.scss` - Variabili Sass
