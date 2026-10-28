import { type Request, type Response } from 'express'
import * as models from '../models/index'

export function orderLookup () {
  return async (req: Request, res: Response) => {
    const [rows] = await models.sequelize.query(`SELECT * FROM Orders WHERE orderId = '${req.params.id}'`)
    res.json(rows)
  }
}
