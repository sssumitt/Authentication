import { connect } from '@planetscale/database'
import config       from './config/config.js'

export const conn = connect({ url: config.db.url })
