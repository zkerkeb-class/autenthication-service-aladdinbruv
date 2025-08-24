import { Request, Response, NextFunction } from 'express';

export const asyncHandler = <T extends (req: Request, res: Response, next: NextFunction) => any>(
  handler: T
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
};


