export function login (req: any, models: any) {
  return models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)
}
