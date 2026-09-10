import { Router, type IRouter } from "express";
import healthRouter from "./health";
import foundationRouter from "./foundation";

const router: IRouter = Router();

router.use(healthRouter);
router.use(foundationRouter);

export default router;
