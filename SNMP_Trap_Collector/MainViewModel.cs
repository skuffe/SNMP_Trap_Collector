// --------------------------------------------------------------------------------------------------------------------
// <copyright file="MainViewModel.cs" company="OxyPlot">
//   http://oxyplot.codeplex.com, license: Ms-PL
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

using OxyPlot;

namespace SNMP_Trap_Collector
{
    public class MainViewModel : Observable
    {
        private PlotModel model;

        public PlotModel Model
        {
            get { return model; }
            set
            {
                if (model != value)
                {
                    model = value;
                    RaisePropertyChanged(() => Model);
                }
            }
        }

    }
}