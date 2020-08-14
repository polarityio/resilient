module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'IBM Resilient',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'RES',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description: 'Query incidents within the IBM Resilient Incident Response Platform',
  entityTypes: ['IPv4', 'domain', 'email', 'hash'],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/resilient.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/block.js'
    },
    template: {
      file: './templates/block.hbs'
    }
  },
  // summary: {
  //   component: {
  //     file: './components/summary.js'
  //   },
  //   template: {
  //     file: './templates/summary.hbs'
  //   }
  // },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',
    /**
     * If set to false, the integeration will ignore SSL errors.  This will allow the integration to connect
     * to servers without valid SSL certificates.  Please note that we do NOT recommending setting this
     * to false in a production environment.
     */
    rejectUnauthorized: true
  },
  logging: {
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'url',
      name: 'Resilient URL',
      description: 'Your Resilient URL',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'username',
      name: 'Resilient Username',
      description: 'Your Resilient username.',
      default: '',
      type: 'text',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'password',
      name: 'Resilient Password',
      description: 'Your Resilient password.',
      default: '',
      type: 'password',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'orgId',
      name: 'Resilient Org ID: ',
      description: 'Your Resilient Org ID',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'searchTypes',
      name: 'Types to Search',
      description: 'Choose the data types that should be searched',
      default: [
        {
          value: 'incident',
          display: 'Incidents'
        }
      ],
      type: 'select',
      options: [
        {
          value: 'incident',
          display: 'Incidents'
        },
        {
          value: 'task',
          display: 'Tasks'
        },
        {
          value: 'note',
          display: 'Notes'
        },
        {
          value: 'artifact',
          display: 'Artifacts'
        }
      ],
      multiple: true,
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'blocklist',
      name: 'Ignored List',
      description: 'List of domains or IPs (space delimited) that you never want to send to DNSDB',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'domainBlocklistRegex',
      name: 'Ignored Domain Regex',
      description:
        'Domains that match the given regex will not be looked up.  Should be set to "Only admins can view and edit".',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    }
  ]
};
