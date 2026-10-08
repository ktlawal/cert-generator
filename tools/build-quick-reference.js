// Builds Apple-Certificate-Quick-Reference.docx, in the style of AppFilter's
// Application-List-Quick-Reference.docx. Needs Node and the "docx" npm package.
//   node tools/build-quick-reference.js "https://<lab-machine>.<domain>:5000/applecert/" Apple-Certificate-Quick-Reference.docx
// The repo copy uses the placeholder; build the handout with the real address
// and do not commit that one.
const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType,
  BorderStyle, ShadingType, AlignmentType, ExternalHyperlink, LevelFormat,
} = require('docx');

const url = process.argv[2];
const out = process.argv[3];

const NAVY = '22254E', GREY = '667085', TEXT = '1F2937', LINE = 'D0D5DD', LINK = '1D4ED8';
const MONO = 'Consolas';
const BODY = 'Calibri';
const W = 9360;                 // 6.5" of text width on US Letter with 1" margins
const COL = [4300, 5060];

const none = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
const thin = { style: BorderStyle.SINGLE, size: 4, color: LINE };

const run = (text, o = {}) => new TextRun({ text, font: o.font || BODY, size: o.size || 21, color: o.color || TEXT,
  bold: o.bold, italics: o.italics, characterSpacing: o.spacing });

function routeRow(route, hint, what) {
  const cell = (children, w) => new TableCell({
    width: { size: w, type: WidthType.DXA }, children,
    margins: { top: 110, bottom: 110, left: 140, right: 140 },
    borders: { top: thin, bottom: thin, left: thin, right: thin },
  });
  return new TableRow({ children: [
    cell([
      new Paragraph({ spacing: { after: 40 }, children: [run(route, { font: MONO, bold: true, size: 21 })] }),
      new Paragraph({ children: [run(hint, { size: 17, color: GREY })] }),
    ], COL[0]),
    cell(what.map(t => new Paragraph({ spacing: { after: 40, line: 276 }, children: [run(t, { size: 19 })] })), COL[1]),
  ] });
}

const bullet = (text) => new Paragraph({ numbering: { reference: 'bullets', level: 0 },
  spacing: { after: 100, line: 264 }, children: [run(text, { size: 20 })] });
const step = (text) => new Paragraph({ numbering: { reference: 'steps', level: 0 },
  spacing: { after: 60, line: 264 }, children: [run(text, { size: 20 })] });
const heading = (text, size = 26, before = 360) => new Paragraph({ spacing: { before, after: 140 },
  children: [run(text, { bold: true, size, color: NAVY })] });

const linkBox = new Table({
  width: { size: W, type: WidthType.DXA }, columnWidths: [W],
  rows: [new TableRow({ children: [new TableCell({
    width: { size: W, type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, color: 'auto', fill: 'F2F4F7' },
    borders: { top: { style: BorderStyle.SINGLE, size: 12, color: NAVY }, bottom: { style: BorderStyle.SINGLE, size: 12, color: NAVY },
               left: { style: BorderStyle.SINGLE, size: 12, color: NAVY }, right: { style: BorderStyle.SINGLE, size: 12, color: NAVY } },
    margins: { top: 260, bottom: 260, left: 200, right: 200 },
    children: [
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [run('APP LINK', { size: 17, bold: true, color: GREY, spacing: 10 })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [
        new ExternalHyperlink({ link: url, children: [new TextRun({ text: url, font: MONO, size: 26, bold: true, color: LINK, underline: {} })] }),
      ] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [run('Edge or Chrome. No sign-in', { size: 18, color: GREY })] }),
    ],
  })] })],
});

const routes = new Table({
  width: { size: W, type: WidthType.DXA }, columnWidths: COL,
  rows: [
    routeRow('/applecert/', 'the front page',
      ['The serial form. Type the serial of the Apple device being decommissioned.']),
    routeRow('/applecert/device?serial=', 'add the serial on the end',
      ['The device as Apple Business has it, any certificates already issued for it, and the wipe details form.']),
    routeRow('/applecert/certificate?id=', 'add the certificate ID on the end',
      ['An issued certificate, ready to print or save as PDF. You get here by pressing Generate certificate.']),
    routeRow('/applecert/health', 'for monitoring',
      ['Returns the word OK. Tells you the service is up — nothing more.']),
  ],
});

const doc = new Document({
  creator: 'IT Asset Management',
  title: 'Apple Device Certificate — Quick Reference',
  styles: { default: { document: { run: { font: BODY, size: 21 } } } },
  numbering: { config: [
    { reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    { reference: 'steps', levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
  ] },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1100, bottom: 900, left: 1440, right: 1440 } } },
    children: [
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 },
        children: [run('PC DECOMMISSIONING — APPLE DEVICES', { size: 18, bold: true, color: GREY, spacing: 60 })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 300 },
        children: [run('Quick Reference', { size: 44, bold: true, color: NAVY })] }),
      linkBox,
      heading('The four routes'),
      routes,
      heading('Issuing a certificate', 22, 300),
      step('Open the app link and type the device’s serial number.'),
      step('Check the device details from Apple Business, and any warning that it already has a certificate.'),
      step('Choose the wipe method, compliance standard and wipe date. Add an asset tag or notes if needed.'),
      step('Press Generate certificate.'),
      step('Press Print and choose Save as PDF, or a printer.'),
      new Paragraph({ spacing: { before: 140, after: 140 }, border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: LINE, space: 1 } }, children: [] }),
      heading('Worth knowing', 22, 120),
      bullet('Issue the certificate before releasing the device from Apple Business. A released device may no longer be found, and then it cannot be certified.'),
      bullet('Device details come straight from Apple Business and cannot be edited here. If something looks wrong, check the device in Apple Business.'),
      bullet('Every certificate has its own ID, such as AC-2026-000001. Reopen one at any time from its address, or from the list on the device page.'),
      bullet('The wipe date can be today or up to 180 days back. Notes can be up to 500 characters and are printed on the certificate.'),
      bullet('If the page doesn’t load, please report it rather than repeatedly refreshing. There may be a service issue.'),
      bullet('Lookups and certificates are logged against your Windows account.'),
    ],
  }],
});

Packer.toBuffer(doc).then(b => { fs.writeFileSync(out, b); console.log('wrote', out); });
